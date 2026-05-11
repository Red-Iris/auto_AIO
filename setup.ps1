# AutoAIO Security Test Platform - One-Click Environment Setup
# Run: .\setup.ps1
# Or if execution policy restricts: powershell -ExecutionPolicy Bypass -File setup.ps1

$ErrorActionPreference = "Stop"
$Host.UI.RawUI.WindowTitle = "AutoAIO Environment Setup"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ConfigFile = Join-Path $ProjectRoot "config.json"
$ToolsDir = Join-Path $ProjectRoot "tools"
$CveVenvDir = Join-Path $ToolsDir "cve-venv"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  AutoAIO Security Test Platform - Environment Setup" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================
# Helper Functions
# ============================================================

function Write-Status($name, $ok, $detail = "") {
    if ($ok) {
        Write-Host "  [OK] " -NoNewline -ForegroundColor Green
        Write-Host "$name" -NoNewline
        if ($detail) { Write-Host " - $detail" -NoNewline -ForegroundColor Gray }
        Write-Host ""
    } else {
        Write-Host "  [MISS] " -NoNewline -ForegroundColor Red
        Write-Host "$name" -NoNewline
        if ($detail) { Write-Host " - $detail" -NoNewline -ForegroundColor Gray }
        Write-Host ""
    }
}

function Test-Command($cmd, $args = "--version") {
    try {
        $result = & $cmd $args 2>&1 | Out-String
        $firstLine = ($result -split "`n")[0].Trim()
        if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne $null) {
            return $false, $null
        }
        return $true, $firstLine
    } catch {
        return $false, $null
    }
}

$allOk = $true

# ============================================================
# Step 1 - Check Python
# ============================================================
Write-Host "[1/5] Checking Python..." -ForegroundColor Yellow
try {
    $pyVersion = python --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Status "Python" $true $pyVersion.Trim()
    } else {
        Write-Status "Python" $false "Not found in PATH"
        $allOk = $false
    }
} catch {
    Write-Status "Python" $false "Not installed"
    Write-Host "         Download: https://www.python.org/downloads/" -ForegroundColor Gray
    Write-Host "         IMPORTANT: Check 'Add Python to PATH' during installation" -ForegroundColor Yellow
    $allOk = $false
}

# ============================================================
# Step 2 - Check Wireshark/TShark
# ============================================================
Write-Host ""
Write-Host "[2/5] Checking Wireshark/TShark..." -ForegroundColor Yellow
$tsharkOk, $tsharkVer = Test-Command "tshark"
if ($tsharkOk) {
    Write-Status "TShark" $true $tsharkVer
} else {
    # Try common paths
    $commonPaths = @(
        "C:\Program Files\Wireshark\tshark.exe",
        "C:\Program Files (x86)\Wireshark\tshark.exe",
        "D:\Wireshark\tshark.exe",
        "E:\Wireshark\tshark.exe"
    )
    $foundPath = $null
    foreach ($p in $commonPaths) {
        if (Test-Path -LiteralPath $p) {
            $foundPath = $p
            break
        }
    }
    if ($foundPath) {
        $tsharkOk2, $tsharkVer2 = Test-Command $foundPath
        Write-Status "TShark" $true "$foundPath - $tsharkVer2"
    } else {
        Write-Status "TShark" $false "Not found"
        Write-Host "         Download: https://www.wireshark.org/download.html" -ForegroundColor Gray
        Write-Host "         IMPORTANT: During installation, check 'Install TShark'" -ForegroundColor Yellow
        $allOk = $false
    }
}

# ============================================================
# Step 3 - Check Nmap
# ============================================================
Write-Host ""
Write-Host "[3/5] Checking Nmap..." -ForegroundColor Yellow
$nmapOk, $nmapVer = Test-Command "nmap"
if ($nmapOk) {
    Write-Status "Nmap" $true $nmapVer
} else {
    Write-Status "Nmap" $false "Not found in PATH"
    Write-Host "         Download: https://nmap.org/download.html" -ForegroundColor Gray
    Write-Host "         IMPORTANT: Check 'Add Nmap to the system PATH'" -ForegroundColor Yellow
    $allOk = $false
}

# ============================================================
# Step 4 - Check OpenSSL
# ============================================================
Write-Host ""
Write-Host "[4/5] Checking OpenSSL..." -ForegroundColor Yellow
$opensslOk, $opensslVer = Test-Command "openssl" "version"
if ($opensslOk) {
    Write-Status "OpenSSL" $true $opensslVer
} else {
    Write-Status "OpenSSL" $false "Not found in PATH"
    Write-Host "         Download: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Gray
    Write-Host "         (Choose the Win64 OpenSSL installer)" -ForegroundColor Gray
    $allOk = $false
}

# ============================================================
# Step 5 - Setup cve-bin-tool (dedicated venv)
# ============================================================
Write-Host ""
Write-Host "[5/5] Setting up cve-bin-tool..." -ForegroundColor Yellow

if (Test-Path -LiteralPath (Join-Path $CveVenvDir "Scripts" "cve-bin-tool.exe")) {
    $cveOk, $cveVer = Test-Command (Join-Path $CveVenvDir "Scripts" "cve-bin-tool.exe")
    Write-Status "cve-bin-tool" $true "(tools/cve-venv) $cveVer"
} else {
    Write-Host "        Creating isolated cve-bin-tool virtual environment..." -ForegroundColor Gray
    Write-Host "        Location: $CveVenvDir" -ForegroundColor Gray

    New-Item -ItemType Directory -Force -Path $ToolsDir | Out-Null

    python -m venv $CveVenvDir
    if ($LASTEXITCODE -ne 0) {
        Write-Status "cve-bin-tool" $false "Failed to create venv"
        $allOk = $false
    } else {
        $pipPath = Join-Path $CveVenvDir "Scripts" "pip.exe"
        Write-Host "        Installing cve-bin-tool (this may take a few minutes)..." -ForegroundColor Gray
        & $pipPath install cve-bin-tool==3.4 -i https://pypi.tuna.tsinghua.edu.cn/simple --quiet 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $cveToolPath = Join-Path $CveVenvDir "Scripts" "cve-bin-tool.exe"
            $cveOk2, $cveVer2 = Test-Command $cveToolPath
            if ($cveOk2) {
                Write-Status "cve-bin-tool" $true $cveVer2
                Write-Host "        cve-bin-tool installed successfully in tools/cve-venv/" -ForegroundColor Green
            } else {
                Write-Status "cve-bin-tool" $false "Installation incomplete"
                $allOk = $false
            }
        } else {
            Write-Status "cve-bin-tool" $false "pip install failed"
            $allOk = $false
        }
    }
}

# ============================================================
# Generate config.json
# ============================================================
Write-Host ""
Write-Host "Generating config.json..." -ForegroundColor Yellow

$config = @{}
if (Test-Path -LiteralPath $ConfigFile) {
    try {
        $existing = Get-Content $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($prop in $existing.PSObject.Properties) {
            $config[$prop.Name] = $prop.Value
        }
    } catch {}
}

# Auto-fill discovered paths
$config['cve_bin_tool_path'] = Join-Path $CveVenvDir "Scripts" "cve-bin-tool.exe"
if ($tsharkOk) {
    $tsharkExePath = (Get-Command tshark -ErrorAction SilentlyContinue).Source
    if ($tsharkExePath) { $config['tshark_path'] = $tsharkExePath }
}

$config | ConvertTo-Json -Depth 3 | Set-Content -Encoding UTF8 -Path $ConfigFile
Write-Host "        Config saved to: $ConfigFile" -ForegroundColor Gray

# ============================================================
# Summary
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
if ($allOk) {
    Write-Host "  All tools ready! You can now run the application." -ForegroundColor Green
} else {
    Write-Host "  Some tools are missing. See download links above." -ForegroundColor Yellow
    Write-Host "  After installing missing tools, re-run this script." -ForegroundColor Yellow
}
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Double-click AutoAIO_Security_Test.exe to launch" -ForegroundColor White
Write-Host "  2. Go to 'System Check' tab to verify all tools are green" -ForegroundColor White
Write-Host "  3. (Optional) Apply for NVD API Key: https://nvd.nist.gov/developers/request-an-api-key" -ForegroundColor White
Write-Host ""

if (-not $allOk) {
    Read-Host "Press Enter to exit"
}
