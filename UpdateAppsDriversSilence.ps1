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

# Function to log messages
function Log-Message {
    param (
        [string]$message,
        [string]$color = "White"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $message"
    Write-Host $logMessage -ForegroundColor $color
    Add-Content -Path "$PSScriptRoot\UpdateLog.txt" -Value $logMessage
}

# Function to update RuckZuck packages
function Update-RuckZuckApps {
    $rzUrl = "https://github.com/rzander/ruckzuck/releases/download/1.7.3.8/RZGet.exe"
    $rzPath = "$PSScriptRoot\RZGet.exe"
    $latestVersion = "1.7.3.8"

    if (Test-Path $rzPath) {
        try {
            $currentVersion = (& $rzPath --version).Split(" ")[-1]
            if ($currentVersion -ne $latestVersion) {
                Log-Message "RuckZuck no está actualizado. Descargando la última versión..." "Yellow"
                Invoke-WebRequest -Uri $rzUrl -OutFile $rzPath
                Log-Message "RuckZuck actualizado correctamente." "Green"
            }
        } catch {
            Log-Message "Error al obtener la versión de RuckZuck: $_" "Red"
        }
    } else {
        Log-Message "RuckZuck no está instalado. Instalando RuckZuck..." "Yellow"
        Invoke-WebRequest -Uri $rzUrl -OutFile $rzPath
        Log-Message "RuckZuck descargado correctamente." "Green"
    }

    try {
        Log-Message "Actualizando paquetes de RuckZuck..." "Cyan"
        & $rzPath update --all --retry --user
        Log-Message "Actualización de paquetes de RuckZuck completada." "Green"
    } catch {
        Log-Message "Error al actualizar paquetes de RuckZuck: $_" "Red"
    }

    try {
        Log-Message "Instalando paquetes no detectados..." "Cyan"
        $missingUpdates = & $rzPath update --list --all --user
        foreach ($update in $missingUpdates) {
            & $rzPath install --name $update.ProductName --vendor $update.Manufacturer --version $update.ProductVersion
        }
        Log-Message "Instalación de paquetes no detectados completada." "Green"
    } catch {
        Log-Message "Error al instalar paquetes no detectados: $_" "Red"
    }
}

# Function to update Winget packages
function Update-WingetApps {
    Log-Message "Verificando la disponibilidad de Winget..." "Cyan"

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Log-Message "Actualizando paquetes de Winget..." "Cyan"
        try {
            winget upgrade --all --include-unknown --accept-package-agreements --force
            Log-Message "Actualización de paquetes de Winget completada." "Green"
        } catch {
            Log-Message "Error al actualizar paquetes de Winget: $_" "Red"
        }
    } else {
        Log-Message "Winget no está instalado. Instalando Winget..." "Yellow"
        try {
            Invoke-WebRequest -Uri "https://aka.ms/getwinget" -OutFile "$env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
            Add-AppxPackage -Path "$env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
            Log-Message "Winget instalado correctamente." "Green"
            Update-WingetApps
        } catch {
            Log-Message "Error al instalar Winget: $_" "Red"
        }
    }
}

# Function to update Windows Store apps
function Update-WindowsStoreApps {
    if (Is-Server) {
        Log-Message "Sistema operativo detectado como servidor. Omitiendo actualizaciones de la Tienda Windows." "Yellow"
        return
    }

    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
        Log-Message "Actualizando aplicaciones de la Tienda Windows..." "Cyan"
        try {
            $apps = Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01"
            if ($apps) {
                $apps | Invoke-CimMethod -MethodName UpdateScanMethod
                Log-Message "Actualización de aplicaciones de la Tienda Windows completada." "Green"
            } else {
                Log-Message "No se encontraron aplicaciones para actualizar." "Yellow"
            }
        } catch {
            Log-Message "Error al actualizar aplicaciones de la Tienda Windows: $_" "Red"
        }
    } else {
        Log-Message "La Tienda Windows no está disponible. Saltando actualizaciones de la Tienda Windows." "Yellow"
    }
}

# Function to update drivers from Windows Update
function Update-Drivers {
    Log-Message "Se conectó a Windows Update en busca de drivers y actualizaciones..." "Cyan"
    $UpdateSearcher = New-Object -Com Microsoft.Update.Searcher
    Log-Message "Se inició la búsqueda de drivers y actualizaciones..." "Cyan"
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0")

    # Inicializar la barra de progreso
    $progress = 0
    $totalUpdates = $SearchResult.Updates.Count
    $UpdatesToDownload = New-Object -Com Microsoft.Update.UpdateColl

    foreach ($Update in $SearchResult.Updates) {
        $UpdatesToDownload.Add($Update) | Out-Null
        Log-Message "Encontrado controlador o Actualizacion: $($Update.Title)" "Cyan"
        $progress++
        Write-Progress -Activity "Buscando drivers" -Status "$progress de $totalUpdates encontrados" -PercentComplete (($progress / $totalUpdates) * 100)
    }

    # Verificación de que la variable $UpdatesToDownload no esté vacía
    if ($UpdatesToDownload.Count -eq 0) {
        Log-Message "No hay actualizaciones disponibles para descargar." "Yellow"
        return
    }

    try {
        Log-Message "Iniciando sesión de actualización..." "Cyan"
        $UpdateSession = New-Object -Com Microsoft.Update.Session
        $Downloader = $UpdateSession.CreateUpdateDownloader()
        $Downloader.Updates = $UpdatesToDownload
        if (-not $Downloader.Updates) {
            throw "No hay actualizaciones para descargar."
        }
        Log-Message "Descargando actualizaciones..." "Cyan"
        $Downloader.Download()
        Log-Message "Descarga completada." "Green"
    } catch {
        Log-Message "Error al descargar las actualizaciones: $_" "Red"
        return
    }

    # Verificar si los controladores están descargados y desencadenar la instalación
    try {
        $UpdatesToInstall = New-Object -Com Microsoft.Update.UpdateColl
        $UpdatesToDownload | ForEach-Object {
            if ($_.IsDownloaded) {
                $UpdatesToInstall.Add($_) | Out-Null
                Log-Message "Instalando controlador: $($_.Title)" "Cyan"
            }
        }
        if ($UpdatesToInstall.Count -eq 0) {
            throw "No hay actualizaciones descargadas para instalar."
        }
        Log-Message 'Instalando controladores o actualizacion...' "Green"
        $Installer = $UpdateSession.CreateUpdateInstaller()
        $Installer.Updates = $UpdatesToInstall
        $InstallationResult = $Installer.Install()
        if ($InstallationResult.RebootRequired) {
            Log-Message '¡Reinicio requerido! Por favor, reinicie ahora.' "Red"
        } else {
            Log-Message 'Instalación completada.' "Green"
        }
    } catch {
        Log-Message "Error durante la instalación: $_" "Red"
    }
}

# Main execution
Log-Message "Iniciando actualizaciones automáticas de aplicaciones y drivers..." "Cyan"
Update-RuckZuckApps
Update-WingetApps
Update-WindowsStoreApps
Update-Drivers
