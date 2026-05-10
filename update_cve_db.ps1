$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$CveBinTool = Join-Path $ProjectRoot ".venv\Scripts\cve-bin-tool.exe"
$PatchDir = Join-Path $ProjectRoot "cve_patch"

if (-not (Test-Path -LiteralPath $VenvPython)) {
    Write-Error "未找到虚拟环境 Python: $VenvPython"
}

if (-not (Test-Path -LiteralPath $CveBinTool)) {
    Write-Error "未找到 cve-bin-tool: $CveBinTool"
}

New-Item -ItemType Directory -Force -Path $PatchDir | Out-Null

@"
try:
    import aiohttp.resolver as _resolver
    import aiohttp.connector as _connector
    _resolver.DefaultResolver = _resolver.ThreadedResolver
    _connector.DefaultResolver = _resolver.ThreadedResolver
except Exception:
    pass
"@ | Set-Content -Encoding UTF8 -Path (Join-Path $PatchDir "sitecustomize.py")

$env:AIOHTTP_NO_EXTENSIONS = "1"
$env:PYTHONPATH = $PatchDir

Write-Host "使用 cve-bin-tool: $CveBinTool"
Write-Host "已启用 aiohttp ThreadedResolver 补丁: $PatchDir"
Write-Host "开始更新 cve-bin-tool 数据库..."

& $CveBinTool -u now -n json-mirror --disable-data-source GAD,EPSS --version

Write-Host "数据库更新命令执行完成。"
