# Actualizacion de Aplicaciones automatica y Drivers desde Windows Update
# Autor: Daniel Landivar
# Licencia: CC BY-NC (Reconocimiento-NoComercial)

# Créditos:
# Editor: Microsoft Copilot
# RuckZuck: https://github.com/rzander/ruckzuck, https://ruckzuck.tools/
# Winget: https://github.com/microsoft/winget-cli
# Windows Update: Microsoft

# Function to check if the system is a server
function Is-Server {
    $os = Get-WmiObject Win32_OperatingSystem
    return $os.ProductType -ne 1
}

# Function to update RuckZuck packages
# Función para actualizar RuckZuck y mostrar detalles de las actualizaciones

function Update-RuckZuckApps {
    $rzPath = "$PSScriptRoot\RZGet.exe"
    $rzVersion = "1.7.3.8"
    $rzDownloadUrl = "https://github.com/rzander/ruckzuck/releases/download/$rzVersion/RZGet.exe"

    # Verificar si RZGet.exe existe
    if (!(Test-Path $rzPath)) {
        Write-Host "📥 RZGet.exe no encontrado. Descargando versión $rzVersion..." -ForegroundColor Yellow
        try {
            Invoke-WebRequest -Uri $rzDownloadUrl -OutFile $rzPath -UseBasicParsing
            Write-Host "✅ RZGet.exe descargado correctamente." -ForegroundColor Green
        } catch {
            Write-Host "❌ Error al descargar RZGet.exe: $_" -ForegroundColor Red
            return
        }
    }

    # Buscar actualizaciones disponibles
    Write-Host "`n🔍 Verificando aplicaciones con actualizaciones disponibles mediante RZGet..." -ForegroundColor Cyan
    try {
        $updatesList = & $rzPath update --list --all --user
        if ($updatesList -match "No updates available") {
            Write-Host "✅ No hay actualizaciones pendientes." -ForegroundColor Green
            return
        }

        $updatesArray = $updatesList -split "`n" |
            Where-Object { $_ -match "^\s*\- " } |
            ForEach-Object { $_ -replace "^\s*\- ", "" }

        if ($updatesArray.Count -gt 0) {
            Write-Host "`n✨ Aplicaciones con actualizaciones disponibles:" -ForegroundColor Yellow
            $updatesArray | ForEach-Object { Write-Host " - $_" -ForegroundColor White }

            Write-Host "`n🔄 Iniciando actualización de todas las aplicaciones con RZGet..." -ForegroundColor Cyan
            & $rzPath update --all --retry --user

            Write-Host "`n✅ Actualización completada. Aplicaciones actualizadas:" -ForegroundColor Green
            $updatesArray | ForEach-Object { Write-Host " - $_" -ForegroundColor White }
        }
    } catch {
        Write-Host "❌ Error al verificar o actualizar aplicaciones con RZGet: $_" -ForegroundColor Red
    }
}

function Get-LatestRZGetVersion {
    Write-Host "🔍 Buscando la última versión de RZGet..." -ForegroundColor Cyan
    $repoUrl = "https://api.github.com/repos/rzander/rzget/releases/latest"

    try {
        $latestInfo = Invoke-RestMethod -Uri $repoUrl -ErrorAction Stop
        return $latestInfo.tag_name
    } catch {
        Write-Host "❌ Error al obtener la última versión de RZGet: $_" -ForegroundColor Red
        return $null
    }
}



# Function to update Winget packages
function Update-WinGetApps {
    Write-Host "`n=== Actualizando aplicaciones con WinGet... ===" -ForegroundColor Cyan

    # Verificar si WinGet está instalado
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "WinGet no está instalado en este sistema. No se pueden actualizar las aplicaciones." -ForegroundColor Red
        return
    }

    # Verificar conexión a Internet
    Write-Host "Verificando conexión a Internet..." -ForegroundColor Yellow
    $ping = Test-Connection -ComputerName www.microsoft.com -Count 1 -Quiet
    if (-not $ping) {
        Write-Host "Error: No hay conexión a Internet. No se pueden actualizar las aplicaciones." -ForegroundColor Red
        return
    }

    # Obtener la lista de aplicaciones que tienen actualizaciones disponibles
    Write-Host "`nVerificando aplicaciones con actualizaciones disponibles..." -ForegroundColor Yellow
    try {
        $updates = winget upgrade --accept-source-agreements | Out-String
        if ($updates -match "No installed package found matching input criteria") {
            Write-Host "No hay actualizaciones disponibles para las aplicaciones." -ForegroundColor Green
            return
        }

        # Extraer los nombres de las aplicaciones con actualización disponible
        $updatesList = $updates -split "`n" | Where-Object { $_ -match "^\S+" } | ForEach-Object { ($_ -split "\s{2,}")[0] }

        if ($updatesList.Count -gt 0) {
            Write-Host "`nAplicaciones con actualizaciones disponibles:" -ForegroundColor Yellow
            $updatesList | ForEach-Object { Write-Host " - $_" -ForegroundColor White }

            # Ejecutar la actualización de todas las aplicaciones
            Write-Host "`nIniciando actualización de aplicaciones con WinGet..." -ForegroundColor Cyan
            winget upgrade --all --silent --force --accept-package-agreements --accept-source-agreements

            Write-Host "`nActualización completada. Aplicaciones actualizadas:" -ForegroundColor Green
            $updatesList | ForEach-Object { Write-Host " - $_" -ForegroundColor White }
        }
    } catch {
        Write-Host "Error al actualizar aplicaciones con WinGet: $_" -ForegroundColor Red
    }
}

# Function to update Windows Store apps
function Update-MicrosoftStore {
    Write-Host "`n=== Actualizando Microsoft Store... ===" -ForegroundColor Cyan

    # Verificar si la Microsoft Store está instalada
    $storeApp = Get-AppxPackage -Name Microsoft.WindowsStore -ErrorAction SilentlyContinue
    if (-not $storeApp) {
        Write-Host "❌ Microsoft Store no está instalada en este sistema." -ForegroundColor Red
        return
    }

    # Verificar conexión a Internet
    Write-Host "🔍 Verificando conexión a Internet..." -ForegroundColor Yellow
    $ping = Test-Connection -ComputerName www.microsoft.com -Count 1 -Quiet
    if (-not $ping) {
        Write-Host "❌ No hay conexión a Internet. No se puede actualizar la Microsoft Store." -ForegroundColor Red
        return
    }

    try {
        # Reiniciar servicios necesarios
        Write-Host "🔄 Reiniciando servicios necesarios para la actualización..." -ForegroundColor Yellow
        Stop-Service -Name wuauserv, cryptsvc -Force -ErrorAction SilentlyContinue
        Start-Service -Name wuauserv, cryptsvc -PassThru | ForEach-Object {
            Write-Host "✅ Servicio $($_.Name) iniciado correctamente."
        }

        # Verificar si wsreset.exe existe antes de ejecutarlo
        $wsresetPath = "C:\Windows\System32\wsreset.exe"
        if (Test-Path $wsresetPath) {
            Write-Host "🔄 Ejecutando limpieza de caché de la Microsoft Store..." -ForegroundColor Yellow
            Start-Process -NoNewWindow -FilePath $wsresetPath -Wait
        } else {
            Write-Host "⚠️ wsreset.exe no encontrado. Saltando limpieza de caché." -ForegroundColor Yellow
        }

        # Actualizar todas las aplicaciones de la Microsoft Store
        Write-Host "🔄 Forzando actualización de todas las aplicaciones de la Microsoft Store..." -ForegroundColor Yellow
        Start-Process -NoNewWindow -FilePath "winget" -ArgumentList "upgrade --all --accept-package-agreements --accept-source-agreements" -Wait

        Write-Host "✅ Actualización de la Microsoft Store completada." -ForegroundColor Green
    }
    catch {
        Write-Host "❌ Error al actualizar la Microsoft Store: $_" -ForegroundColor Red
    }

    # Opción de reparación si la tienda está dañada
    if (-not (Get-AppxPackage -Name Microsoft.WindowsStore -ErrorAction SilentlyContinue)) {
        Write-Host "⚠️ La Microsoft Store parece estar dañada. Intentando reinstalar..." -ForegroundColor Yellow
        try {
            Get-AppxPackage -allusers Microsoft.WindowsStore | ForEach-Object {
                Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"
            }
            Write-Host "✅ Microsoft Store reinstalada correctamente." -ForegroundColor Green
        } catch {
            Write-Host "❌ Error al reinstalar la Microsoft Store: $_" -ForegroundColor Red
        }
    }
}

# Función para actualizar drivers y actualizaciones de Windows
function Update-WindowsDriversAndUpdates {
    Write-Host "`n=== Iniciando actualización de drivers y actualizaciones de Windows... ===" -ForegroundColor Cyan

    # Verificar conexión a Internet
    Write-Host "🔍 Verificando conexión a Internet..." -ForegroundColor Yellow
    if (-not (Test-Connection -ComputerName 8.8.8.8 -Count 2 -Quiet)) {
        Write-Host "❌ No hay conexión a Internet. Abortando actualización..." -ForegroundColor Red
        return
    }

    # Reiniciar servicios de Windows Update
    Write-Host "🔄 Reiniciando servicios de Windows Update..." -ForegroundColor Yellow
    $services = @("wuauserv", "cryptsvc")
    Try {
        $services | ForEach-Object {
            Stop-Service -Name $_ -Force -ErrorAction SilentlyContinue
            Start-Service -Name $_ -ErrorAction Stop
            Write-Host "✅ Servicio $_ reiniciado correctamente." -ForegroundColor Green
        }
    } Catch {
        Write-Host "⚠️ No se pudieron reiniciar algunos servicios: $_" -ForegroundColor Yellow
    }

    # Instalar o importar PSWindowsUpdate
    if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-Host "📥 Instalando módulo PSWindowsUpdate..." -ForegroundColor Yellow
        Try {
            Install-Module PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber
            Import-Module PSWindowsUpdate
        } Catch {
            Write-Host "❌ Error al instalar PSWindowsUpdate: $_" -ForegroundColor Red
            return
        }
    } else {
        Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
    }

    # Buscar e instalar actualizaciones
    Write-Host "🔍 Buscando actualizaciones de Windows y drivers..." -ForegroundColor Yellow
    try {
        Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -IgnoreReboot | Out-Null
        Write-Host "✅ Actualizaciones instaladas correctamente." -ForegroundColor Green
    } catch {
        Write-Host "❌ Error durante la actualización de Windows y drivers: $_" -ForegroundColor Red
    }

    # Verificar si es necesario reiniciar
    if (Get-PendingReboot) {
        Write-Host "⚠️ Se requiere reiniciar el sistema para aplicar cambios." -ForegroundColor Yellow
    } else {
        Write-Host "✅ No es necesario reiniciar el sistema." -ForegroundColor Green
    }
}

# Función para verificar si se requiere reinicio del sistema
function Get-PendingReboot {
    Write-Host "🔄 Verificando si es necesario reiniciar el equipo..." -ForegroundColor Yellow

    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations'
    )

    foreach ($key in $keys) {
        if (Test-Path $key) {
            Write-Host "⚠️ Se requiere reiniciar el sistema para aplicar cambios." -ForegroundColor Yellow
            return $true
        }
    }

    Write-Host "✅ No es necesario reiniciar el sistema." -ForegroundColor Green
    return $false
}

# Main execution
Write-Host "Iniciando actualizaciones automáticas de aplicaciones y drivers..." -ForegroundColor Cyan
Update-RuckZuckApps
Update-WingetApps
Update-MicrosoftStore
Update-WindowsDriversAndUpdates
