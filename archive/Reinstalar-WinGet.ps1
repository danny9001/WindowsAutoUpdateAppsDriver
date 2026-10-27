#Requires -RunAsAdministrator

# ============================================
# SCRIPT DEFINITIVO DE INSTALACION DE WINGET
# Para Windows 10 LTSC
# Incluye todas las dependencias necesarias
# ============================================

$ErrorActionPreference = "SilentlyContinue"
$progressPreference = 'silentlyContinue'

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  INSTALACION DEFINITIVA DE WINGET" -ForegroundColor Cyan
Write-Host "  Windows 10 LTSC Edition" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================
# PASO 1: LIMPIEZA TOTAL
# ============================================
Write-Host "[1/6] Limpiando instalaciones previas..." -ForegroundColor Yellow

# Desinstalar WinGet AppX
Get-AppxPackage -Name Microsoft.DesktopAppInstaller -AllUsers | Remove-AppxPackage -AllUsers
Get-AppxPackage -Name Microsoft.DesktopAppInstaller | Remove-AppxPackage

# Eliminar carpeta manual
if (Test-Path "C:\WinGet") {
    Remove-Item "C:\WinGet" -Recurse -Force
    Write-Host "  Carpeta C:\WinGet eliminada" -ForegroundColor Gray
}

# Limpiar PATH del sistema
$machinePath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
$machinePath = $machinePath -replace ";?C:\\WinGet;?", ""
$machinePath = $machinePath.TrimEnd(';')
[Environment]::SetEnvironmentVariable("Path", $machinePath, [EnvironmentVariableTarget]::Machine)

# Limpiar PATH del usuario
$userPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
$userPath = $userPath -replace ";?$env:LOCALAPPDATA\\Microsoft\\WindowsApps;?", ""
$userPath = $userPath.TrimEnd(';')
[Environment]::SetEnvironmentVariable("Path", $userPath, [EnvironmentVariableTarget]::User)

Write-Host "  Limpieza completada" -ForegroundColor Green
Write-Host ""

# ============================================
# PASO 2: INSTALAR VISUAL C++ REDISTRIBUTABLE
# ============================================
Write-Host "[2/6] Instalando Visual C++ Redistributable..." -ForegroundColor Yellow

$tempVC = "$env:TEMP\VCRedist"
New-Item -ItemType Directory -Path $tempVC -Force | Out-Null

Write-Host "  Descargando VC++ 2015-2022 (x64)..." -ForegroundColor Gray
$vcRedistUrl = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
$vcRedistPath = "$tempVC\vc_redist.x64.exe"
Invoke-WebRequest -Uri $vcRedistUrl -OutFile $vcRedistPath

Write-Host "  Instalando (esto puede tardar un momento)..." -ForegroundColor Gray
Start-Process -FilePath $vcRedistPath -ArgumentList "/install", "/quiet", "/norestart" -Wait

Remove-Item $tempVC -Recurse -Force
Write-Host "  Visual C++ Redistributable instalado" -ForegroundColor Green
Write-Host ""

# ============================================
# PASO 3: DESCARGAR COMPONENTES DE WINGET
# ============================================
Write-Host "[3/6] Descargando componentes de WinGet..." -ForegroundColor Yellow

$tempFolder = "$env:TEMP\WinGetInstall"
New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null
Set-Location $tempFolder

# VCLibs (dependencia AppX)
Write-Host "  Descargando VCLibs..." -ForegroundColor Gray
Invoke-WebRequest -Uri "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx" -OutFile "VCLibs.appx"

# UI.Xaml (dependencia LTSC)
Write-Host "  Descargando UI.Xaml..." -ForegroundColor Gray
Invoke-WebRequest -Uri "https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx" -OutFile "UIXaml.appx"

# WinGet
Write-Host "  Descargando WinGet..." -ForegroundColor Gray
$latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
$wingetUrl = ($latestRelease.assets | Where-Object { $_.name -like "*.msixbundle" }).browser_download_url
$licenseUrl = ($latestRelease.assets | Where-Object { $_.name -like "*License1.xml" }).browser_download_url

Invoke-WebRequest -Uri $wingetUrl -OutFile "WinGet.msixbundle"
Invoke-WebRequest -Uri $licenseUrl -OutFile "License.xml"

Write-Host "  Descarga completada" -ForegroundColor Green
Write-Host ""

# ============================================
# PASO 4: INSTALAR DEPENDENCIAS APPX
# ============================================
Write-Host "[4/6] Instalando dependencias AppX..." -ForegroundColor Yellow

Write-Host "  Instalando VCLibs..." -ForegroundColor Gray
Add-AppxPackage -Path "VCLibs.appx"

Write-Host "  Instalando UI.Xaml..." -ForegroundColor Gray
Add-AppxPackage -Path "UIXaml.appx"

Write-Host "  Dependencias AppX instaladas" -ForegroundColor Green
Write-Host ""

# ============================================
# PASO 5: INSTALAR WINGET
# ============================================
Write-Host "[5/6] Instalando WinGet..." -ForegroundColor Yellow

Write-Host "  Instalando para todos los usuarios..." -ForegroundColor Gray
Add-AppxProvisionedPackage -Online -PackagePath "WinGet.msixbundle" -LicensePath "License.xml"

Write-Host "  Instalando para usuario actual..." -ForegroundColor Gray
Add-AppxPackage -Path "WinGet.msixbundle"

Write-Host "  WinGet instalado" -ForegroundColor Green
Write-Host ""

# ============================================
# PASO 6: CONFIGURAR ACCESO PERMANENTE
# ============================================
Write-Host "[6/6] Configurando acceso permanente..." -ForegroundColor Yellow

# Esperar a que Windows registre el paquete
Start-Sleep -Seconds 3

# Verificar instalación
$wingetPackage = Get-AppxPackage -Name Microsoft.DesktopAppInstaller
if (!$wingetPackage) {
    Write-Host "  ERROR: WinGet no se instalo correctamente" -ForegroundColor Red
    Set-Location $env:TEMP
    Remove-Item $tempFolder -Recurse -Force
    exit
}

$wingetSource = $wingetPackage.InstallLocation
Write-Host "  WinGet ubicado en: $wingetSource" -ForegroundColor Gray

# Crear carpeta permanente
$wingetDest = "C:\WinGet"
New-Item -ItemType Directory -Path $wingetDest -Force | Out-Null

# Copiar TODO el contenido
Write-Host "  Copiando archivos a C:\WinGet..." -ForegroundColor Gray
Copy-Item -Path "$wingetSource\*" -Destination $wingetDest -Recurse -Force

# Configurar permisos
Write-Host "  Configurando permisos..." -ForegroundColor Gray
icacls $wingetDest /grant "Users:(OI)(CI)RX" /T | Out-Null
icacls $wingetDest /grant "Administrators:(OI)(CI)F" /T | Out-Null

# Agregar al PATH del sistema
$currentPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine)
if ($currentPath -notlike "*$wingetDest*") {
    $newPath = "$currentPath;$wingetDest"
    [Environment]::SetEnvironmentVariable("Path", $newPath, [EnvironmentVariableTarget]::Machine)
    $env:Path = $newPath
    Write-Host "  PATH del sistema actualizado" -ForegroundColor Gray
}

Write-Host "  Configuracion completada" -ForegroundColor Green
Write-Host ""

# Limpiar archivos temporales
Set-Location $env:TEMP
Remove-Item $tempFolder -Recurse -Force

# ============================================
# VERIFICACION FINAL
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  VERIFICACION DE INSTALACION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verificar paquete
$installedPackage = Get-AppxPackage -Name Microsoft.DesktopAppInstaller
if ($installedPackage) {
    Write-Host "Paquete AppX:" -ForegroundColor Green
    Write-Host "  Nombre: $($installedPackage.Name)" -ForegroundColor Gray
    Write-Host "  Version: $($installedPackage.Version)" -ForegroundColor Gray
    Write-Host ""
}

# Verificar archivos
if (Test-Path "$wingetDest\winget.exe") {
    Write-Host "Ejecutable:" -ForegroundColor Green
    Write-Host "  Ubicacion: $wingetDest\winget.exe" -ForegroundColor Gray
    Write-Host ""
}

# Verificar DLL critica
if (Test-Path "$wingetDest\MSVCP140.dll") {
    Write-Host "Dependencia MSVCP140.dll: Encontrada en carpeta WinGet" -ForegroundColor Green
} else {
    # Verificar en System32
    if (Test-Path "C:\Windows\System32\MSVCP140.dll") {
        Write-Host "Dependencia MSVCP140.dll: Encontrada en System32" -ForegroundColor Green
    } else {
        Write-Host "ADVERTENCIA: MSVCP140.dll no encontrada" -ForegroundColor Yellow
        Write-Host "  VC++ Redistributable puede no haberse instalado correctamente" -ForegroundColor Yellow
    }
}
Write-Host ""

# Probar ejecución
Write-Host "Probando WinGet..." -ForegroundColor Yellow
$testOutput = & "$wingetDest\winget.exe" --version 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "EXITO: WinGet funciona correctamente" -ForegroundColor Green
    Write-Host "Version: $testOutput" -ForegroundColor Gray
    Write-Host ""
} else {
    Write-Host "ERROR al ejecutar WinGet:" -ForegroundColor Red
    Write-Host $testOutput -ForegroundColor Red
    Write-Host ""
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  INSTALACION FINALIZADA" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "PASOS SIGUIENTES:" -ForegroundColor Yellow
Write-Host "1. Cierra esta ventana de PowerShell" -ForegroundColor White
Write-Host "2. Abre una NUEVA ventana (normal, no necesita ser Admin)" -ForegroundColor White
Write-Host "3. Ejecuta estos comandos:" -ForegroundColor White
Write-Host ""
Write-Host "   winget --version" -ForegroundColor Cyan
Write-Host "   winget search notepad++" -ForegroundColor Cyan
Write-Host "   winget install Notepad++.Notepad++" -ForegroundColor Cyan
Write-Host ""
Write-Host "Si hay algun problema, ejecuta:" -ForegroundColor Yellow
Write-Host "   C:\WinGet\winget.exe --version" -ForegroundColor Cyan
Write-Host ""