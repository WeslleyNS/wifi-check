# =============================================================================
# NetDiag Agent — Bootstrap Windows (PowerShell)
# Uso: iwr -useb https://raw.githubusercontent.com/WeslleyNS/wifi-check/main/install.ps1 | iex
# =============================================================================
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "       NetDiag Agent - Diagnostico de Rede        " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Verificar Python 3
# ---------------------------------------------------------------------------
$pythonCmd = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd -c "import sys; print(sys.version_info.major)" 2>$null
        if ($ver -ge 3) { $pythonCmd = $cmd; break }
    } catch {}
}

if (-not $pythonCmd) {
    Write-Host "ERRO: Python 3 nao encontrado." -ForegroundColor Red
    Write-Host "Instale em: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "Marque 'Add Python to PATH' durante a instalacao." -ForegroundColor Yellow
    exit 1
}

$pyVersion = & $pythonCmd --version 2>&1
Write-Host ("Python detectado: " + $pyVersion) -ForegroundColor Green

# ---------------------------------------------------------------------------
# 2. Baixar o projeto
# ---------------------------------------------------------------------------
$tmpDir = Join-Path $env:TEMP ("netdiag-" + (Get-Random))
New-Item -ItemType Directory -Path $tmpDir | Out-Null
$zipPath = Join-Path $tmpDir "netdiag.zip"
$projectDir = Join-Path $tmpDir "wifi-check-main"

Write-Host "Baixando NetDiag Agent do GitHub..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri "https://github.com/WeslleyNS/wifi-check/archive/refs/heads/main.zip" -OutFile $zipPath -UseBasicParsing
} catch {
    curl.exe -fsSL "https://github.com/WeslleyNS/wifi-check/archive/refs/heads/main.zip" -o $zipPath
}

Expand-Archive -Path $zipPath -DestinationPath $tmpDir -Force
Write-Host "Download concluido" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Rodar diagnostico e capturar saida
# ---------------------------------------------------------------------------
Set-Location $projectDir

Write-Host ""
Write-Host "Iniciando diagnostico de rede (30s)..." -ForegroundColor Yellow
Write-Host "   (execute como Administrador para dados mais completos)"
Write-Host ""

$oldEap = $ErrorActionPreference
$ErrorActionPreference = "Continue"

$outputLines = @()
& $pythonCmd run.py doctor --duration 30 2>&1 | ForEach-Object {
    $line = $_.ToString()
    Write-Host $line
    $outputLines += $line
}

$ErrorActionPreference = $oldEap

# ---------------------------------------------------------------------------
# 4. Extrair caminho do HTML da saida do tool
# ---------------------------------------------------------------------------
$htmlPath = $null

foreach ($line in $outputLines) {
    if ($line -match '\[HTML\].*:\s*(.+\.html)') {
        $htmlPath = $Matches[1].Trim()
        break
    }
}

# Fallback: procurar no Desktop / NetDiag-Logs via registro do Windows (funciona com OneDrive)
if (-not $htmlPath -or -not (Test-Path $htmlPath)) {
    try {
        $regKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        $desktopRaw = (Get-ItemProperty -Path $regKey -Name "Desktop").Desktop
        $desktop = [System.Environment]::ExpandEnvironmentVariables($desktopRaw)
        $logsDir = Join-Path $desktop "NetDiag-Logs"
        if (Test-Path $logsDir) {
            $htmlPath = Get-ChildItem -Path $logsDir -Filter "netdiag-report-*.html" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1 -ExpandProperty FullName
        }
        if (-not $htmlPath -and (Test-Path $desktop)) {
            $htmlPath = Get-ChildItem -Path $desktop -Filter "netdiag-report-*.html" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime | Select-Object -Last 1 -ExpandProperty FullName
        }
    } catch {}
}

# ---------------------------------------------------------------------------
# 5. Abrir relatorio no navegador
# ---------------------------------------------------------------------------
Write-Host ""
if ($htmlPath -and (Test-Path $htmlPath)) {
    Write-Host ("Relatorio gerado: " + $htmlPath) -ForegroundColor Green
    Write-Host "Abrindo no navegador..." -ForegroundColor Cyan
    Start-Process $htmlPath
} else {
    Write-Host "Relatorio nao encontrado automaticamente." -ForegroundColor Yellow
    Write-Host "Verifique a saida acima para o caminho do arquivo HTML."
}

Write-Host ""
Write-Host "Dica: para monitoramento continuo, execute:" -ForegroundColor Cyan
Write-Host ("  " + $pythonCmd + " run.py collect --daemon --interval 30")
Write-Host ""

# Cleanup
Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
