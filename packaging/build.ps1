<#
.SYNOPSIS
  Builds Syslog Monitor for Windows: portable ZIP and (if Inno Setup is available) installer.

.DESCRIPTION
  1. Creates an isolated build environment under %LOCALAPPDATA%\SyslogMonitor-build
  2. Runs tests (can be skipped with -SkipTests)
  3. Builds with PyInstaller (onedir: faster startup and fewer antivirus false positives than one-file)
  4. Collects license texts for all bundled packages (LICENSE.txt, THIRD-PARTY-NOTICES.txt, licenses\)
  5. dist\SyslogMonitor-<Version>-portable.zip and dist\SyslogMonitor-<Version>-setup.exe

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File packaging\build.ps1
#>
param(
    [switch]$SkipTests,
    [string]$PythonVersion = "3.11",
    [string]$WorkRoot = (Join-Path $env:LOCALAPPDATA "SyslogMonitor-build")
)
$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Dist = Join-Path $ProjectRoot "dist"
$Venv = Join-Path $WorkRoot "venv"
$VenvPy = Join-Path $Venv "Scripts\python.exe"
$Stage = Join-Path $WorkRoot "pyinstaller"

function Invoke-Checked([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Fehlgeschlagen ($LASTEXITCODE): $Exe $($Arguments -join ' ')" }
}

Write-Host "== Build-Umgebung: $Venv"
if (-not (Test-Path $VenvPy)) {
    Invoke-Checked "py" @("-$PythonVersion", "-m", "venv", $Venv)
}
Invoke-Checked $VenvPy @("-m", "pip", "install", "--quiet", "--upgrade", "pip")
Invoke-Checked $VenvPy @("-m", "pip", "install", "--quiet", "$ProjectRoot[test]", "pyinstaller>=6.10")
# A non-editable install leaves setuptools artefacts in the project folder.
Remove-Item -Recurse -Force (Join-Path $ProjectRoot "build") -ErrorAction SilentlyContinue
Get-ChildItem (Join-Path $ProjectRoot "src") -Filter "*.egg-info" -Directory | Remove-Item -Recurse -Force

$Version = (& $VenvPy -c "import syslog_monitor; print(syslog_monitor.__version__)").Trim()
Write-Host "== Version $Version"

if (-not $SkipTests) {
    Write-Host "== Tests"
    Push-Location $ProjectRoot
    try { Invoke-Checked $VenvPy @("-m", "pytest", "-q", "-p", "no:cacheprovider") } finally { Pop-Location }
}

Write-Host "== Icon"
$Icon = Join-Path $WorkRoot "SyslogMonitor.ico"
Invoke-Checked $VenvPy @((Join-Path $PSScriptRoot "make_icon.py"), $Icon)

Write-Host "== PyInstaller"
Invoke-Checked $VenvPy @(
    "-m", "PyInstaller", "--noconfirm", "--clean", "--windowed",
    "--name", "SyslogMonitor", "--icon", $Icon,
    "--distpath", (Join-Path $Stage "dist"), "--workpath", (Join-Path $Stage "work"),
    "--specpath", $Stage,
    # uvicorn (MCP server) loads protocol/loop modules by name.
    "--collect-submodules", "uvicorn",
    # optional imports (anyio's pytest plugin, syntax highlighting) that are never used at runtime
    "--exclude-module", "pytest", "--exclude-module", "_pytest", "--exclude-module", "pygments",
    (Join-Path $PSScriptRoot "launcher.py"))
$AppDir = Join-Path $Stage "dist\SyslogMonitor"
if (-not (Test-Path (Join-Path $AppDir "SyslogMonitor.exe"))) { throw "SyslogMonitor.exe was not created" }

Write-Host "== Lizenztexte"
Invoke-Checked $VenvPy @((Join-Path $PSScriptRoot "collect_licenses.py"), $AppDir,
                         (Join-Path $Stage "work\SyslogMonitor\PYZ-00.pyz"), $ProjectRoot)

New-Item -ItemType Directory -Force $Dist | Out-Null
$Zip = Join-Path $Dist "SyslogMonitor-$Version-portable.zip"
Write-Host "== ZIP: $Zip"
Remove-Item $Zip -ErrorAction SilentlyContinue
Compress-Archive -Path $AppDir -DestinationPath $Zip -CompressionLevel Optimal

$Iscc = @(
    (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source,
    (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"),
    (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
    (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe")
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if ($Iscc) {
    Write-Host "== Installer (Inno Setup)"
    Invoke-Checked $Iscc @("/Q", "/DAppVersion=$Version", "/DSourceDir=$AppDir", "/DIconFile=$Icon",
                           "/DOutputDir=$Dist", (Join-Path $PSScriptRoot "installer.iss"))
} else {
    Write-Warning "Inno Setup not found; created only the ZIP (winget install JRSoftware.InnoSetup --scope user)."
}

Write-Host ""
Write-Host "Done:"
Get-ChildItem $Dist -Filter "SyslogMonitor-$Version-*" | ForEach-Object {
    "  {0}  ({1:N1} MB)" -f $_.FullName, ($_.Length / 1MB)
}
