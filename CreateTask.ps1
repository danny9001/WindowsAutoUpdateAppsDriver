# Script para crear una tarea programada que ejecute UpdateAppsDrivers3.ps1 todos los días
# Autor: Daniel Landivar
# Código libre de modificación
# Licencia: CC BY-NC (Reconocimiento-NoComercial)

# Créditos:
# Editor: Microsoft Copilot

# Solicitar la hora de ejecución de la tarea
$hour = Read-Host "Ingrese la hora de ejecución de la tarea (formato 24 horas, ej. 03 para las 3 AM, 14 para las 2 PM)"
$minute = Read-Host "Ingrese los minutos de ejecución de la tarea (ej. 30 para las 2:30 PM)"

# Solicitar la ubicación y nombre de la carpeta donde se copiará el script
$folderPath = Read-Host "Ingrese la ubicación y nombre de la carpeta donde se copiará el script (ej. C:\ScriptAutoUpdate)"

# Verificar si la carpeta existe, si no, crearla
if (-not (Test-Path $folderPath)) {
    New-Item -Path $folderPath -ItemType Directory
    Write-Host "Carpeta $folderPath creada." -Fore Green
} else {
    Write-Host "La carpeta $folderPath ya existe." -Fore Yellow
}

# Crear carpeta de logs si no existe
$logFolder = "$folderPath\Logs"
if (-not (Test-Path $logFolder)) {
    New-Item -Path $logFolder -ItemType Directory
    Write-Host "Carpeta de logs creada en $folderPath" -Fore Green
} else {
    Write-Host "La carpeta de logs ya existe en $folderPath" -Fore Yellow
}

# Copiar el script UpdateAppsDrivers3.ps1 a la carpeta especificada
$scriptSource = "$PSScriptRoot\UpdateAppsDrivers3.ps1"
$scriptDestination = "$folderPath\UpdateAppsDrivers3.ps1"
Copy-Item -Path $scriptSource -Destination $scriptDestination -Force
Write-Host "Script UpdateAppsDrivers3.ps1 copiado a $folderPath" -Fore Green

# Crear la tarea programada
$taskName = "DailyUpdateAppsDrivers"
$taskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File `"$scriptDestination`""
$taskTime = [datetime]::ParseExact("${hour}:${minute}", "HH:mm", $null)
$taskTrigger = New-ScheduledTaskTrigger -Daily -At $taskTime
$taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -DontStopOnIdleEnd -StartWhenAvailable
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount

Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal
Write-Host "Tarea programada creada para ejecutar UpdateAppsDrivers3.ps1 todos los días a las ${hour}:${minute}" -Fore Green