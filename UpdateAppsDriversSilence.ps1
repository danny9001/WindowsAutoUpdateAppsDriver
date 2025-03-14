# Actualizacion de Aplicaciones automatica y Drivers desde Windows Update
# Autor: Daniel Landivar
# Licencia: CC BY-NC (Reconocimiento-NoComercial)

# Créditos:
# Editor: Microsoft Copilot
# RuckZuck: https://github.com/rzander/ruckzuck, https://ruckzuck.tools/
# Chocolatey: https://chocolatey.org
# Winget: https://github.com/microsoft/winget-cli
# Windows Update: Microsoft

# Function to check if the system is a server
function Is-Server {
    $os = Get-WmiObject Win32_OperatingSystem
    return $os.ProductType -ne 1
}

# Function to update Windows Store apps
function Update-WindowsStoreApps {
    if (Is-Server) {
        Write-Log "Sistema operativo detectado como servidor. Omitiendo actualizaciones de la Tienda Windows."
        return
    }

    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
        Write-Log "Actualizando aplicaciones de la Tienda Windows..."
        try {
            Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" |
            Invoke-CimMethod -MethodName UpdateScanMethod
            Write-Log "Actualización de aplicaciones de la Tienda Windows completada."
        } catch {
            Write-Log "Error al actualizar aplicaciones de la Tienda Windows: $_"
        }
    } else {
        Write-Log "La Tienda Windows no está disponible. Saltando actualizaciones de la Tienda Windows."
    }
}

# Function to update Chocolatey packages
function Update-ChocolateyApps {
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Log "Actualizando paquetes de Chocolatey..."
        try {
            choco upgrade all -y
            Write-Log "Actualización de paquetes de Chocolatey completada."
        } catch {
            Write-Log "Error al actualizar paquetes de Chocolatey: $_"
        }
    } else {
        Write-Log "Chocolatey no está instalado. Instalando Chocolatey..."
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            Write-Log "Chocolatey instalado correctamente."
            Update-ChocolateyApps
        } catch {
            Write-Log "Error al instalar Chocolatey: $_"
        }
    }
}

# Function to update Winget packages
function Update-WingetApps {
    if (Is-Server) {
        Write-Log "Sistema operativo detectado como servidor. Omitiendo actualizaciones de Winget."
        return
    }

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Log "Actualizando paquetes de Winget..."
        try {
            winget upgrade --all
            Write-Log "Actualización de paquetes de Winget completada."
        } catch {
            Write-Log "Error al actualizar paquetes de Winget: $_"
        }
    } else {
        Write-Log "Winget no está instalado. Saltando actualizaciones de Winget."
    }
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
                Write-Log "RuckZuck no está actualizado. Descargando la última versión..."
                Invoke-WebRequest -Uri $rzUrl -OutFile $rzPath
                Write-Log "RuckZuck actualizado correctamente."
            }
        } catch {
            Write-Log "Error al obtener la versión de RuckZuck: $_"
        }
    } else {
        Write-Log "RuckZuck no está instalado. Instalando RuckZuck..."
        Invoke-WebRequest -Uri $rzUrl -OutFile $rzPath
        Write-Log "RuckZuck descargado correctamente."
    }

    try {
        Write-Log "Actualizando paquetes de RuckZuck..."
        & $rzPath update --all
        Write-Log "Actualización de paquetes de RuckZuck completada."
    } catch {
        Write-Log "Error al actualizar paquetes de RuckZuck: $_"
    }
}

# Function to update drivers from Windows Update
function Update-Drivers {
    Write-Log "Se conectó a Windows Update en busca de drivers..."
    $UpdateSearcher = New-Object -Com Microsoft.Update.Searcher
    Write-Log "Se inició la búsqueda de drivers..."
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0")

    # Inicializar la barra de progreso
    $progress = 0
    $totalUpdates = $SearchResult.Updates.Count

    $UpdatesToDownload = New-Object -Com Microsoft.Update.UpdateColl
    foreach ($Update in $SearchResult.Updates) {
        $UpdatesToDownload.Add($Update) | Out-Null
        Write-Log "Encontrado controlador: $($Update.Title)"
        $progress++
        Write-Progress -Activity "Buscando drivers" -Status "$progress de $totalUpdates encontrados" -PercentComplete (($progress / $totalUpdates) * 100)
    }

    # Verificación de que la variable $UpdatesToDownload no esté vacía
    if ($UpdatesToDownload.Count -eq 0) {
        Write-Log "No hay actualizaciones disponibles para descargar."
        return
    }

    try {
        Write-Log "Iniciando sesión de actualización..."
        $UpdateSession = New-Object -Com Microsoft.Update.Session
        $Downloader = $UpdateSession.CreateUpdateDownloader()
        $Downloader.Updates = $UpdatesToDownload

        if (-not $Downloader.Updates) {
            throw "No hay actualizaciones para descargar."
        }

        Write-Log "Descargando actualizaciones..."
        $Downloader.Download()
        Write-Log "Descarga completada."
    } catch {
        Write-Log "Error al descargar las actualizaciones: $_"
        return
    }

    # Verificar si los controladores están descargados y desencadenar la instalación
    try {
        $UpdatesToInstall = New-Object -Com Microsoft.Update.UpdateColl

        $UpdatesToDownload | ForEach-Object {
            if ($_.IsDownloaded) {
                $UpdatesToInstall.Add($_) | Out-Null
                Write-Log "Instalando controlador: $($_.Title)"
            }
        }

        if ($UpdatesToInstall.Count -eq 0) {
            throw "No hay actualizaciones descargadas para instalar."
        }

        Write-Log 'Instalando controladores...'
        $Installer = $UpdateSession.CreateUpdateInstaller()
        $Installer.Updates = $UpdatesToInstall
        $InstallationResult = $Installer.Install()

        if ($InstallationResult.RebootRequired) {
            Write-Log '¡Reinicio requerido! Por favor, reinicie ahora.'
        } else {
            Write-Log 'Instalación completada.'
        }
    } catch {
        Write-Log "Error durante la instalación: $_"
    }
}

# Function to write logs
function Write-Log {
    param (
        [string]$message
    )
    $logFile = "$PSScriptRoot\Logs\UpdateLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    Add-Content -Path $logFile -Value $message
}

# Main execution
Write-Log "Iniciando actualizaciones automáticas de aplicaciones y drivers..."
Update-WindowsStoreApps
Update-ChocolateyApps
Update-WingetApps
Update-RuckZuckApps
Update-Drivers
Write-Log "Proceso de actualización completado."