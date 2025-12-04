#requires -Version 5.0
<#
.SYNOPSIS
  Crea una tarea programada para ejecutar el actualizador automático

.DESCRIPTION
  Script optimizado para Windows 10 PowerShell 5.0/5.1
  Crea una tarea programada que ejecuta UpdateAppsDriversSilence.ps1 diariamente

.NOTES
  Autor: Daniel Landivar
  Licencia: CC BY-NC (Reconocimiento-NoComercial)
  Requiere: Permisos de administrador
  Optimizado para: Windows PowerShell 5.0/5.1

.CREDITS
  Editor: Microsoft Copilot
#>

[CmdletBinding()]
param()

# -------------------------
# Verificar privilegios de administrador
# -------------------------
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "ADVERTENCIA: Este script requiere privilegios de administrador." -ForegroundColor Red
    Write-Host "Por favor, ejecute PowerShell como administrador y vuelva a intentarlo." -ForegroundColor Yellow
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Configurador de Tarea Programada" -ForegroundColor Cyan
Write-Host "  Actualizador Automático Windows 10" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# -------------------------
# Seleccionar script a programar
# -------------------------
Write-Host "Scripts disponibles:" -ForegroundColor Yellow
Write-Host "  1. UpdateAppsDriversSilence.ps1 (Recomendado - Optimizado para Windows 10)" -ForegroundColor White
Write-Host "  2. UpdateAppsDrivers6.ps1 (Avanzado - Requiere PowerShell 5.1+)" -ForegroundColor White
Write-Host ""

$scriptChoice = Read-Host "Seleccione el script a programar (1 o 2) [Por defecto: 1]"
if ([string]::IsNullOrWhiteSpace($scriptChoice)) { $scriptChoice = "1" }

$scriptName = switch ($scriptChoice) {
    "1" { "UpdateAppsDriversSilence.ps1" }
    "2" { "UpdateAppsDrivers6.ps1" }
    default { "UpdateAppsDriversSilence.ps1" }
}

Write-Host "Script seleccionado: $scriptName" -ForegroundColor Green
Write-Host ""

# -------------------------
# Configuración de la tarea
# -------------------------
$hour = Read-Host "Ingrese la hora de ejecución (formato 24h, ej: 03 para 3 AM, 14 para 2 PM)"
$minute = Read-Host "Ingrese los minutos de ejecución (ej: 00, 30)"

# Validar entrada
if ([string]::IsNullOrWhiteSpace($hour)) { $hour = "03" }
if ([string]::IsNullOrWhiteSpace($minute)) { $minute = "00" }

$hour = $hour.PadLeft(2, '0')
$minute = $minute.PadLeft(2, '0')

Write-Host ""
$folderPath = Read-Host "Ruta de destino [Por defecto: C:\AutoUpdate]"
if ([string]::IsNullOrWhiteSpace($folderPath)) {
    $folderPath = "C:\AutoUpdate"
}

# -------------------------
# Crear estructura de carpetas
# -------------------------
try {
    if (-not (Test-Path $folderPath)) {
        New-Item -Path $folderPath -ItemType Directory -Force | Out-Null
        Write-Host "✓ Carpeta creada: $folderPath" -ForegroundColor Green
    } else {
        Write-Host "✓ Carpeta existe: $folderPath" -ForegroundColor Yellow
    }

    $logFolder = Join-Path $folderPath "Logs"
    if (-not (Test-Path $logFolder)) {
        New-Item -Path $logFolder -ItemType Directory -Force | Out-Null
        Write-Host "✓ Carpeta de logs creada: $logFolder" -ForegroundColor Green
    } else {
        Write-Host "✓ Carpeta de logs existe: $logFolder" -ForegroundColor Yellow
    }
} catch {
    Write-Host "✗ Error al crear carpetas: $_" -ForegroundColor Red
    exit 1
}

# -------------------------
# Copiar script
# -------------------------
$scriptSource = Join-Path $PSScriptRoot $scriptName
$scriptDestination = Join-Path $folderPath $scriptName

if (-not (Test-Path $scriptSource)) {
    Write-Host "✗ ERROR: No se encontró el script: $scriptSource" -ForegroundColor Red
    Write-Host "Asegúrese de que el script exista en la misma carpeta." -ForegroundColor Yellow
    exit 1
}

try {
    if ($scriptSource -ne $scriptDestination) {
        Copy-Item -Path $scriptSource -Destination $scriptDestination -Force
        Write-Host "✓ Script copiado: $scriptDestination" -ForegroundColor Green
    } else {
        Write-Host "✓ Script en ubicación correcta" -ForegroundColor Green
    }
} catch {
    Write-Host "✗ Error al copiar script: $_" -ForegroundColor Red
    exit 1
}

# -------------------------
# Crear tarea programada
# -------------------------
try {
    $taskName = "AutoUpdateWindows10"
    $taskDescription = "Actualización automática de aplicaciones y drivers para Windows 10"

    # Verificar si la tarea ya existe
    $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Write-Host "⚠ La tarea '$taskName' ya existe. Se eliminará y recreará." -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }

    # Configurar acción
    $taskAction = New-ScheduledTaskAction `
        -Execute "PowerShell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptDestination`""

    # Configurar trigger (diario a la hora especificada)
    $taskTime = [datetime]::ParseExact("${hour}:${minute}", "HH:mm", $null)
    $taskTrigger = New-ScheduledTaskTrigger -Daily -At $taskTime

    # Configurar settings
    $taskSettings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -DontStopOnIdleEnd `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 10)

    # Configurar principal (ejecutar como SYSTEM)
    $taskPrincipal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest

    # Registrar tarea
    Register-ScheduledTask `
        -TaskName $taskName `
        -Description $taskDescription `
        -Action $taskAction `
        -Trigger $taskTrigger `
        -Settings $taskSettings `
        -Principal $taskPrincipal | Out-Null

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  ✓ TAREA PROGRAMADA CREADA" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "Nombre: $taskName" -ForegroundColor White
    Write-Host "Script: $scriptName" -ForegroundColor White
    Write-Host "Horario: Todos los días a las ${hour}:${minute}" -ForegroundColor White
    Write-Host "Usuario: SYSTEM" -ForegroundColor White
    Write-Host "Logs: $logFolder" -ForegroundColor White
    Write-Host ""
    Write-Host "Para ver la tarea: taskschd.msc" -ForegroundColor Yellow
    Write-Host "Para ejecutar ahora: Start-ScheduledTask -TaskName '$taskName'" -ForegroundColor Yellow

} catch {
    Write-Host "✗ Error al crear tarea programada: $_" -ForegroundColor Red
    exit 1
}
