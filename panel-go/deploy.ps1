# deploy.ps1 — удалённый деплой Paylater Monitor (Go) на Windows через SSH.
# Сервер: 172.31.32.23, служба: PaylaterMonitor (NSSM, auto-start).

param(
    [string]$Server      = "172.31.32.23",
    [string]$User         = "programm",
    [string]$Password     = 'PdjybnJktym$%',
    [string]$HostKey      = "SHA256:tfpnFL+Ayy4hixpv1UvA9ConUh1hZIiuTEVYCXtnglM",
    [string]$SitePath     = "C:\paylater-mon",
    [string]$ServiceName  = "PaylaterMonitor",
    [string]$NSSMUrl      = "https://nssm.cc/release/nssm-2.24.zip",
    [string]$ConfigPath   = "config.yaml"
)

$ErrorActionPreference = "Stop"

# ── Поиск plink/pscp ──
$plink = $null
$pscp  = $null
foreach ($p in @("C:\plink\plink.exe", "plink.exe")) { if (Get-Command $p -ErrorAction SilentlyContinue) { $plink = $p; break } }
foreach ($p in @("C:\plink\pscp.exe", "pscp.exe"))   { if (Get-Command $p -ErrorAction SilentlyContinue) { $pscp  = $p; break } }
if (-not $plink -or -not $pscp) {
    Write-Error "plink.exe и pscp.exe не найдены. Установите PuTTY или разместите в C:\plink\"
    exit 1
}

Write-Host "============================================="  -ForegroundColor Cyan
Write-Host "  Paylater Monitor (Go) — Remote Deploy"          -ForegroundColor Cyan
Write-Host "  Server: $Server"                                  -ForegroundColor Cyan
Write-Host "  Service: $ServiceName — NSSM, auto-start"        -ForegroundColor Cyan
Write-Host "============================================="  -ForegroundColor Cyan

# ── [1/5] Сборка ──
Write-Host "[1/5] Сборка бинарника..." -ForegroundColor Yellow
go build -o paylater-mon.exe ./cmd/server
if ($LASTEXITCODE -ne 0) { Write-Host "ОШИБКА сборки!" -ForegroundColor Red; exit 1 }
Write-Host "  OK" -ForegroundColor Green

# ── [2/5] Подготовка пакета ──
Write-Host "[2/5] Упаковка артефактов..." -ForegroundColor Yellow
$staging = Join-Path $env:TEMP "paylater-mon-staging"
if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
New-Item -ItemType Directory -Path $staging -Force | Out-Null

Copy-Item "paylater-mon.exe"           "$staging\paylater-mon.exe" -Force
Copy-Item $ConfigPath                  "$staging\config.yaml"      -Force
Copy-Item "static"                     "$staging\static"           -Force -Recurse
Copy-Item 'internal\web\templates'     "$staging\templates"        -Force -Recurse

# Загрузка NSSM локально и включение в пакет (на удалённом сервере нет интернет-доступа)
$nssmLocalZip = Join-Path $env:TEMP "nssm-2.24.zip"
$nssmLocalDir = Join-Path $env:TEMP "nssm-extract"
$prevProgress = $ProgressPreference
$ProgressPreference = 'SilentlyContinue'
Write-Host "  Загрузка NSSM..." -ForegroundColor Yellow
Invoke-WebRequest -Uri $NSSMUrl -OutFile $nssmLocalZip -UseBasicParsing
if (Test-Path $nssmLocalDir) { Remove-Item $nssmLocalDir -Recurse -Force }
New-Item -ItemType Directory -Path $nssmLocalDir -Force | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory($nssmLocalZip, $nssmLocalDir)
$nssmExeLocal = Get-ChildItem -Path $nssmLocalDir -Recurse -Filter "nssm.exe" | Select-Object -First 1
if (-not $nssmExeLocal) { Write-Error "NSSM не найден в скачанном архиве"; exit 1 }
Copy-Item $nssmExeLocal.FullName "$staging\nssm.exe" -Force
Remove-Item $nssmLocalZip -Force -ErrorAction SilentlyContinue
Remove-Item $nssmLocalDir -Recurse -Force -ErrorAction SilentlyContinue
$ProgressPreference = $prevProgress

$zipFile = Join-Path $env:TEMP "paylater-mon-deploy.zip"
if (Test-Path $zipFile) { Remove-Item $zipFile -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($staging, $zipFile)
Write-Host "  OK" -ForegroundColor Green

# ── [3/5] Копирование на сервер ──
Write-Host "[3/5] Копирование пакета на $Server..." -ForegroundColor Yellow
$pscpArgs = @("-batch", "-hostkey", $HostKey, "-pw", $Password, $zipFile, "${User}@${Server}:C:\paylater-mon-deploy.zip")
$proc = Start-Process -FilePath $pscp -ArgumentList $pscpArgs -NoNewWindow -Wait -PassThru
if ($proc.ExitCode -ne 0) { Write-Error "SCP failed (exit code $($proc.ExitCode))"; exit 1 }
Write-Host "  OK" -ForegroundColor Green

# ── [4/5] Удалённый деплой: stop → delete → deploy → create service → start ──
Write-Host "[4/5] Удалённый деплой и управление службой..." -ForegroundColor Yellow

$remoteScript = @"
`$ErrorActionPreference = "Stop"

`$SitePath    = "$SitePath"
`$ServiceName = "$ServiceName"
`$ZipFile     = "C:\paylater-mon-deploy.zip"
`$NSSMDir     = "C:\nssm"
`$NSSMExe     = "C:\nssm\nssm.exe"

Write-Host "[remote] Остановка службы (если существует)..."
`$svc = Get-Service -Name `$ServiceName -ErrorAction SilentlyContinue
if (`$svc) {
    if (`$svc.Status -eq "Running") {
        Stop-Service -Name `$ServiceName -Force
        Start-Sleep -Seconds 3
    }
    Write-Host "[remote] Удаление службы..."
    sc.exe delete `$ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

Write-Host "[remote] Распаковка пакета..."
if (Test-Path "`${SitePath}_new") { Remove-Item "`${SitePath}_new" -Recurse -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory(`$ZipFile, "`${SitePath}_new")

Write-Host "[remote] Замена файлов (сохраняем config.yaml)..."
if (Test-Path `$SitePath) {
    if (Test-Path "`$SitePath\config.yaml") {
        Copy-Item "`$SitePath\config.yaml" "`${SitePath}_new\config.yaml" -Force
    }
    Remove-Item `$SitePath -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path `$SitePath) { Remove-Item `$SitePath -Recurse -Force -ErrorAction SilentlyContinue }
}
Rename-Item "`${SitePath}_new" `$SitePath

Write-Host "[remote] Удаление пакета..."
Remove-Item `$ZipFile -Force -ErrorAction SilentlyContinue

Write-Host "[remote] Установка NSSM из пакета..."
if (-not (Test-Path `$NSSMDir)) { New-Item -ItemType Directory -Path `$NSSMDir -Force | Out-Null }
if (Test-Path "`$SitePath\nssm.exe") {
    Copy-Item "`$SitePath\nssm.exe" `$NSSMExe -Force -ErrorAction SilentlyContinue
}
if (-not (Test-Path `$NSSMExe)) {
    Write-Error "NSSM не найден в пакете деплоя и не установлен на сервере."
    exit 1
}

Write-Host "[remote] Создание службы `$ServiceName..."
& `$NSSMExe install `$ServiceName "`$SitePath\paylater-mon.exe"
& `$NSSMExe set `$ServiceName AppDirectory `$SitePath
& `$NSSMExe set `$ServiceName AppParameters "-config config.yaml"
& `$NSSMExe set `$ServiceName AppStdout "`$SitePath\logs\stdout.log"
& `$NSSMExe set `$ServiceName AppStderr "`$SitePath\logs\stderr.log"
& `$NSSMExe set `$ServiceName AppRotateFiles 1
& `$NSSMExe set `$ServiceName AppRotateBytes 10485760
& `$NSSMExe set `$ServiceName Start SERVICE_AUTO_START
& `$NSSMExe set `$ServiceName Description "Paylater Monitor — единая панель мониторинга (Go)"

Write-Host "[remote] Запуск службы..."
Start-Service -Name `$ServiceName
Start-Sleep -Seconds 3

`$svc = Get-Service -Name `$ServiceName -ErrorAction SilentlyContinue
if (`$svc -and `$svc.Status -eq "Running") {
    Write-Host "[remote] Служба запущена. Статус: Running"
} else {
    Write-Error "[remote] Служба не запустилась! Проверьте логи: `$SitePath\logs\"
    exit 1
}

Write-Host "[remote] Деплой завершён успешно."
"@

# Write remote script to temp file and SCP it to server
$remoteScriptFile = Join-Path $env:TEMP "paylater-mon-remote.ps1"
$remoteScript | Out-File -FilePath $remoteScriptFile -Encoding UTF8
$pscpRemoteArgs = @("-batch", "-hostkey", $HostKey, "-pw", $Password, $remoteScriptFile, "${User}@${Server}:C:\paylater-mon-remote.ps1")
$procScp = Start-Process -FilePath $pscp -ArgumentList $pscpRemoteArgs -NoNewWindow -Wait -PassThru
if ($procScp.ExitCode -ne 0) { Write-Error "SCP remote script failed (exit code $($procScp.ExitCode))"; exit 1 }

$plinkArgs = @("-batch", "-hostkey", $HostKey, "-pw", $Password, "${User}@${Server}", "powershell -ExecutionPolicy Bypass -File C:\paylater-mon-remote.ps1")
$proc2 = Start-Process -FilePath $plink -ArgumentList $plinkArgs -NoNewWindow -Wait -PassThru
if ($proc2.ExitCode -ne 0) { Write-Error "Remote deploy failed (exit code $($proc2.ExitCode))"; exit 1 }
Write-Host "  OK" -ForegroundColor Green

# ── [5/5] Проверка ──
Write-Host "[5/5] Проверка службы..." -ForegroundColor Yellow
$checkScript = @"
`$svc = Get-Service -Name "$ServiceName" -ErrorAction SilentlyContinue
if (`$svc) {
    Write-Host "Service: `$(`$svc.Name)"
    Write-Host "Status:  `$(`$svc.Status)"
    Write-Host "StartType: `$(`$svc.StartType)"
} else {
    Write-Host "Service not found!"
    exit 1
}
"@
$checkScriptFile = Join-Path $env:TEMP "paylater-mon-check.ps1"
$checkScript | Out-File -FilePath $checkScriptFile -Encoding UTF8
$pscpCheckArgs = @("-batch", "-hostkey", $HostKey, "-pw", $Password, $checkScriptFile, "${User}@${Server}:C:\paylater-mon-check.ps1")
$procScpCheck = Start-Process -FilePath $pscp -ArgumentList $pscpCheckArgs -NoNewWindow -Wait -PassThru
if ($procScpCheck.ExitCode -ne 0) { Write-Host "  WARNING: не удалось скопировать скрипт проверки" -ForegroundColor Yellow }
$plinkArgs2 = @("-batch", "-hostkey", $HostKey, "-pw", $Password, "${User}@${Server}", "powershell -ExecutionPolicy Bypass -File C:\paylater-mon-check.ps1")
$proc3 = Start-Process -FilePath $plink -ArgumentList $plinkArgs2 -NoNewWindow -Wait -PassThru
if ($proc3.ExitCode -ne 0) { Write-Host "  WARNING: проверка службы не удалась" -ForegroundColor Yellow }
Write-Host "  OK" -ForegroundColor Green

# ── Очистка локальных временных файлов ──
Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $zipFile -Force -ErrorAction SilentlyContinue
Remove-Item $remoteScriptFile -Force -ErrorAction SilentlyContinue
Remove-Item $checkScriptFile -Force -ErrorAction SilentlyContinue

# ── Очистка удалённых временных файлов ──
$cleanupArgs = @("-batch", "-hostkey", $HostKey, "-pw", $Password, "${User}@${Server}", "del C:\paylater-mon-remote.ps1 C:\paylater-mon-check.ps1")
$null = Start-Process -FilePath $plink -ArgumentList $cleanupArgs -NoNewWindow -Wait -PassThru

Write-Host ""
Write-Host "============================================="  -ForegroundColor Green
Write-Host "  DEPLOY COMPLETED SUCCESSFULLY"                 -ForegroundColor Green
Write-Host "  URL: http://${Server}:9090"                     -ForegroundColor Green
Write-Host "  Service: $ServiceName — NSSM, auto-start"      -ForegroundColor Green
Write-Host "============================================="  -ForegroundColor Green
