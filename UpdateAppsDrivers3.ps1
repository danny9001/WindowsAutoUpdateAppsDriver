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
        Write-Host "Sistema operativo detectado como servidor. Omitiendo actualizaciones de la Tienda Windows." -Fore Yellow
        return
    }

    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
        Write-Host "Actualizando aplicaciones de la Tienda Windows..." -Fore Cyan
        try {
            Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" |
            Invoke-CimMethod -MethodName UpdateScanMethod
            Write-Host "Actualización de aplicaciones de la Tienda Windows completada." -Fore Green
        } catch {
            Write-Host "Error al actualizar aplicaciones de la Tienda Windows: $_" -Fore Red
        }
    } else {
        Write-Host "La Tienda Windows no está disponible. Saltando actualizaciones de la Tienda Windows." -Fore Yellow
    }
}

# Function to update Chocolatey packages
function Update-ChocolateyApps {
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Host "Actualizando paquetes de Chocolatey..." -Fore Cyan
        try {
            choco upgrade all -y
            Write-Host "Actualización de paquetes de Chocolatey completada." -Fore Green
        } catch {
            Write-Host "Error al actualizar paquetes de Chocolatey: $_" -Fore Red
        }
    } else {
        Write-Host "Chocolatey no está instalado. Instalando Chocolatey..." -Fore Yellow
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force
            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            Write-Host "Chocolatey instalado correctamente." -Fore Green
            Update-ChocolateyApps
        } catch {
            Write-Host "Error al instalar Chocolatey: $_" -Fore Red
        }
    }
}

# Function to update Winget packages
function Update-WingetApps {
    if (Is-Server) {
        Write-Host "Sistema operativo detectado como servidor. Omitiendo actualizaciones de Winget." -Fore Yellow
        return
    }

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "Actualizando paquetes de Winget..." -Fore Cyan
        try {
            winget upgrade --all
            Write-Host "Actualización de paquetes de Winget completada." -Fore Green
        } catch {
            Write-Host "Error al actualizar paquetes de Winget: $_" -Fore Red
        }
    } else {
        Write-Host "Winget no está instalado. Saltando actualizaciones de Winget." -Fore Yellow
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
                Write-Host "RuckZuck no está actualizado. Descargando la última versión..." -Fore Yellow
                Invoke-WebRequest -Uri $rzUrl -OutFile $rzPath
                Write-Host "RuckZuck actualizado correctamente." -Fore Green
            }
        } catch {
            Write-Host "Error al obtener la versión de RuckZuck: $_" -Fore Red
        }
    } else {
        Write-Host "RuckZuck no está instalado. Instalando RuckZuck..." -Fore Yellow
        Invoke-WebRequest -Uri $rzUrl -OutFile $rzPath
        Write-Host "RuckZuck descargado correctamente." -Fore Green
    }

    try {
        Write-Host "Actualizando paquetes de RuckZuck..." -Fore Cyan
        & $rzPath update --all
        Write-Host "Actualización de paquetes de RuckZuck completada." -Fore Green
    } catch {
        Write-Host "Error al actualizar paquetes de RuckZuck: $_" -Fore Red
    }
}

# Function to update drivers from Windows Update
function Update-Drivers {
    Write-Host "Se conectó a Windows Update en busca de drivers..." -Fore Cyan
    $UpdateSearcher = New-Object -Com Microsoft.Update.Searcher
    Write-Host "Se inició la búsqueda de drivers..." -Fore Cyan
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0")

    # Inicializar la barra de progreso
    $progress = 0
    $totalUpdates = $SearchResult.Updates.Count

    $UpdatesToDownload = New-Object -Com Microsoft.Update.UpdateColl
    foreach ($Update in $SearchResult.Updates) {
        $UpdatesToDownload.Add($Update) | Out-Null
        Write-Host "Encontrado controlador: $($Update.Title)" -Fore Cyan
        $progress++
        Write-Progress -Activity "Buscando drivers" -Status "$progress de $totalUpdates encontrados" -PercentComplete (($progress / $totalUpdates) * 100)
    }

    # Verificación de que la variable $UpdatesToDownload no esté vacía
    if ($UpdatesToDownload.Count -eq 0) {
        Write-Host "No hay actualizaciones disponibles para descargar." -Fore Yellow
        return
    }

    try {
        Write-Host "Iniciando sesión de actualización..." -Fore Cyan
        $UpdateSession = New-Object -Com Microsoft.Update.Session
        $Downloader = $UpdateSession.CreateUpdateDownloader()
        $Downloader.Updates = $UpdatesToDownload

        if (-not $Downloader.Updates) {
            throw "No hay actualizaciones para descargar."
        }

        Write-Host "Descargando actualizaciones..." -Fore Cyan
        $Downloader.Download()
        Write-Host "Descarga completada." -Fore Green
    } catch {
        Write-Host "Error al descargar las actualizaciones: $_" -Fore Red
        return
    }

    # Verificar si los controladores están descargados y desencadenar la instalación
    try {
        $UpdatesToInstall = New-Object -Com Microsoft.Update.UpdateColl

        $UpdatesToDownload | ForEach-Object {
            if ($_.IsDownloaded) {
                $UpdatesToInstall.Add($_) | Out-Null
                Write-Host "Instalando controlador: $($_.Title)" -Fore Cyan
            }
        }

        if ($UpdatesToInstall.Count -eq 0) {
            throw "No hay actualizaciones descargadas para instalar."
        }

        Write-Host 'Instalando controladores...' -Fore Green
        $Installer = $UpdateSession.CreateUpdateInstaller()
        $Installer.Updates = $UpdatesToInstall
        $InstallationResult = $Installer.Install()

        if ($InstallationResult.RebootRequired) {
            Write-Host '¡Reinicio requerido! Por favor, reinicie ahora.' -Fore Red
        } else {
            Write-Host 'Instalación completada.' -Fore Green
        }
    } catch {
        Write-Host "Error durante la instalación: $_" -Fore Red
    }
}

# Main execution
Write-Host "Iniciando actualizaciones automáticas de aplicaciones y drivers..." -Fore Cyan
Update-WindowsStoreApps
Update-ChocolateyApps
Update-WingetApps
Update-RuckZuckApps
Update-Drivers
Write-Host "Proceso de actualización completado." -Fore Green
