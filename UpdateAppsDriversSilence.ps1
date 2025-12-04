#requires -Version 5.0
<#
.SYNOPSIS
  Actualización automática de aplicaciones y drivers desde Windows Update

.DESCRIPTION
  Script optimizado para Windows 10 PowerShell 5.0/5.1
  Actualiza apps (RuckZuck, WinGet, Microsoft Store) y drivers/actualizaciones de Windows

.NOTES
  Autor: Daniel Landivar
  Licencia: CC BY-NC (Reconocimiento-NoComercial)
  Optimizado para: Windows PowerShell 5.0/5.1

.CREDITS
  Editor: Microsoft Copilot
  RuckZuck: https://github.com/rzander/ruckzuck
  WinGet: https://github.com/microsoft/winget-cli
#>

[CmdletBinding()]
param(
    [string]$LogPath = "$PSScriptRoot\Logs"
)

# -------------------------
# Configuración inicial
# -------------------------
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'  # Optimiza rendimiento

# Crear carpeta de logs si no existe
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

$Global:LogFile = Join-Path $LogPath ("UpdateLog_{0:yyyyMMdd_HHmmss}.txt" -f (Get-Date))

# -------------------------
# Funciones de utilidad
# -------------------------

# Habilitar TLS 1.2 para Windows PowerShell 5.1
function Enable-Tls12 {
    try {
        if ($PSVersionTable.PSVersion.Major -lt 6) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
    } catch {
        Log-Message "Advertencia: No se pudo configurar TLS 1.2" "Yellow"
    }
}

# Verificar si es servidor
function Test-IsServer {
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        return ($os.ProductType -ne 1)
    } catch {
        return $false
    }
}

# Sistema de logging optimizado (buffer para reducir I/O)
$Global:LogBuffer = [System.Collections.Generic.List[string]]::new()
$Global:LogBufferSize = 10

function Log-Message {
    param (
        [string]$Message,
        [string]$Color = "White"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"

    # Mostrar en consola
    Write-Host $logMessage -ForegroundColor $Color

    # Agregar al buffer
    $Global:LogBuffer.Add($logMessage)

    # Flush cuando el buffer alcanza el tamaño definido
    if ($Global:LogBuffer.Count -ge $Global:LogBufferSize) {
        Flush-LogBuffer
    }
}

function Flush-LogBuffer {
    if ($Global:LogBuffer.Count -gt 0) {
        try {
            $Global:LogBuffer | Add-Content -Path $Global:LogFile -ErrorAction Stop
            $Global:LogBuffer.Clear()
        } catch {
            Write-Warning "Error al escribir log: $_"
        }
    }
}

# Actualizar paquetes RuckZuck (optimizado para PS 5.0/5.1)
function Update-RuckZuckApps {
    Log-Message "=== Iniciando actualización RuckZuck ===" "Cyan"

    Enable-Tls12
    $rzUrl = "https://github.com/rzander/ruckzuck/releases/latest/download/RZGet.exe"
    $rzPath = Join-Path $PSScriptRoot "RZGet.exe"

    # Descargar o actualizar RZGet.exe
    try {
        if (-not (Test-Path $rzPath)) {
            Log-Message "Descargando RZGet.exe..." "Yellow"
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($rzUrl, $rzPath)
            Log-Message "RZGet.exe descargado correctamente." "Green"
        }
    } catch {
        Log-Message "Error al descargar RZGet.exe: $($_.Exception.Message)" "Red"
        return
    }

    # Actualizar paquetes
    try {
        Log-Message "Buscando actualizaciones de RuckZuck..." "Cyan"
        $updateOutput = & $rzPath update --list --all --user 2>&1

        if ($LASTEXITCODE -eq 0 -and $updateOutput) {
            Log-Message "Aplicando actualizaciones de RuckZuck..." "Cyan"
            & $rzPath update --all --retry --user 2>&1 | Out-Null
            Log-Message "Actualización de RuckZuck completada." "Green"
        } else {
            Log-Message "No hay actualizaciones disponibles en RuckZuck." "Green"
        }
    } catch {
        Log-Message "Error al actualizar RuckZuck: $($_.Exception.Message)" "Red"
    }
}

# Actualizar paquetes WinGet (optimizado para PS 5.0/5.1)
function Update-WingetApps {
    Log-Message "=== Iniciando actualización WinGet ===" "Cyan"

    # Verificar disponibilidad de WinGet
    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    if (-not $wingetCmd) {
        Log-Message "WinGet no está instalado en este sistema." "Yellow"
        Log-Message "Para instalarlo, visite: https://aka.ms/getwinget" "Yellow"
        return
    }

    try {
        # Actualizar fuentes de WinGet
        Log-Message "Actualizando fuentes de WinGet..." "Cyan"
        winget source update --disable-interactivity 2>&1 | Out-Null

        # Listar actualizaciones disponibles
        Log-Message "Buscando actualizaciones de WinGet..." "Cyan"
        $upgradeList = winget upgrade --include-unknown --disable-interactivity 2>&1

        if ($LASTEXITCODE -eq 0) {
            # Aplicar todas las actualizaciones
            Log-Message "Aplicando actualizaciones de WinGet..." "Cyan"
            winget upgrade --all --include-unknown --include-pinned --accept-package-agreements --accept-source-agreements --silent --disable-interactivity 2>&1 | Out-Null

            if ($LASTEXITCODE -eq 0) {
                Log-Message "Actualización de WinGet completada correctamente." "Green"
            } else {
                Log-Message "WinGet completó con advertencias (código: $LASTEXITCODE)." "Yellow"
            }
        } else {
            Log-Message "No hay actualizaciones disponibles en WinGet." "Green"
        }
    } catch {
        Log-Message "Error al actualizar WinGet: $($_.Exception.Message)" "Red"
    }
}

# Actualizar aplicaciones de Microsoft Store (optimizado para PS 5.0/5.1)
function Update-WindowsStoreApps {
    Log-Message "=== Iniciando actualización Microsoft Store ===" "Cyan"

    # Omitir en servidores
    if (Test-IsServer) {
        Log-Message "Sistema servidor detectado. Omitiendo Microsoft Store." "Yellow"
        return
    }

    # Verificar si Store está instalada
    $storeApp = Get-AppxPackage -Name Microsoft.WindowsStore -ErrorAction SilentlyContinue
    if (-not $storeApp) {
        Log-Message "Microsoft Store no está instalada en este sistema." "Yellow"
        return
    }

    try {
        # Resetear caché de la Store
        $wsresetPath = Join-Path $env:SystemRoot "System32\wsreset.exe"
        if (Test-Path $wsresetPath) {
            Log-Message "Limpiando caché de Microsoft Store..." "Cyan"
            Start-Process -FilePath $wsresetPath -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
        }

        # Si WinGet está disponible, usarlo para actualizar Store
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Log-Message "Actualizando apps de Store vía WinGet..." "Cyan"
            winget upgrade --source msstore --all --include-unknown --accept-package-agreements --accept-source-agreements --silent --disable-interactivity 2>&1 | Out-Null
            Log-Message "Actualización de Microsoft Store completada." "Green"
        } else {
            # Método alternativo usando CIM
            try {
                $apps = Get-CimInstance -Namespace "Root\cimv2\mdm\dmmap" -ClassName "MDM_EnterpriseModernAppManagement_AppManagement01" -ErrorAction Stop
                if ($apps) {
                    $apps | Invoke-CimMethod -MethodName UpdateScanMethod -ErrorAction Stop
                    Log-Message "Escaneo de actualizaciones de Store iniciado." "Green"
                } else {
                    Log-Message "No se encontraron aplicaciones de Store." "Yellow"
                }
            } catch {
                Log-Message "Método CIM no disponible. Use WinGet para mejores resultados." "Yellow"
            }
        }
    } catch {
        Log-Message "Error al actualizar Microsoft Store: $($_.Exception.Message)" "Red"
    }
}

# Actualizar drivers desde Windows Update (optimizado para PS 5.0/5.1)
function Update-Drivers {
    Log-Message "=== Iniciando Windows Update (drivers y actualizaciones) ===" "Cyan"

    # Crear objetos COM de Windows Update
    try {
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    } catch {
        Log-Message "Error al inicializar Windows Update: $($_.Exception.Message)" "Red"
        return
    }

    # Buscar actualizaciones
    try {
        Log-Message "Buscando actualizaciones disponibles..." "Cyan"
        $SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software' or Type='Driver'")

        $totalUpdates = $SearchResult.Updates.Count
        if ($totalUpdates -eq 0) {
            Log-Message "No hay actualizaciones disponibles." "Green"
            return
        }

        Log-Message "Encontradas $totalUpdates actualización(es):" "Yellow"

        # Crear colección de actualizaciones a descargar
        $UpdatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
        $counter = 0

        foreach ($Update in $SearchResult.Updates) {
            $counter++
            if ($Update.IsDownloaded -eq $false) {
                $UpdatesToDownload.Add($Update) | Out-Null
                Log-Message "  [$counter/$totalUpdates] $($Update.Title)" "White"
            }
        }

        # Descargar actualizaciones
        if ($UpdatesToDownload.Count -gt 0) {
            Log-Message "Descargando $($UpdatesToDownload.Count) actualización(es)..." "Cyan"

            $Downloader = $UpdateSession.CreateUpdateDownloader()
            $Downloader.Updates = $UpdatesToDownload
            $DownloadResult = $Downloader.Download()

            if ($DownloadResult.ResultCode -eq 2) {
                Log-Message "Descarga completada exitosamente." "Green"
            } else {
                Log-Message "Descarga completada con código: $($DownloadResult.ResultCode)" "Yellow"
            }
        }

        # Instalar actualizaciones descargadas
        $UpdatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($Update in $SearchResult.Updates) {
            if ($Update.IsDownloaded -eq $true) {
                $UpdatesToInstall.Add($Update) | Out-Null
            }
        }

        if ($UpdatesToInstall.Count -gt 0) {
            Log-Message "Instalando $($UpdatesToInstall.Count) actualización(es)..." "Cyan"

            $Installer = $UpdateSession.CreateUpdateInstaller()
            $Installer.Updates = $UpdatesToInstall
            $InstallResult = $Installer.Install()

            # Verificar resultado
            switch ($InstallResult.ResultCode) {
                2 { Log-Message "Instalación completada exitosamente." "Green" }
                3 { Log-Message "Instalación completada con errores." "Yellow" }
                4 { Log-Message "Instalación falló." "Red" }
                5 { Log-Message "Instalación cancelada." "Yellow" }
                default { Log-Message "Instalación completada (código: $($InstallResult.ResultCode))." "Yellow" }
            }

            # Verificar si se requiere reinicio
            if ($InstallResult.RebootRequired) {
                Log-Message "*** REINICIO REQUERIDO para completar la instalación ***" "Red"
            }
        } else {
            Log-Message "No hay actualizaciones nuevas para instalar." "Green"
        }

    } catch {
        Log-Message "Error en Windows Update: $($_.Exception.Message)" "Red"
    } finally {
        # Liberar objetos COM para reducir uso de memoria
        if ($UpdateSearcher) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($UpdateSearcher) | Out-Null }
        if ($UpdateSession) { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($UpdateSession) | Out-Null }
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

# -------------------------
# EJECUCIÓN PRINCIPAL
# -------------------------

Log-Message "========================================" "Cyan"
Log-Message "  Actualizador Automático de Windows 10" "Cyan"
Log-Message "  PowerShell $($PSVersionTable.PSVersion)" "Cyan"
Log-Message "  Log: $Global:LogFile" "Cyan"
Log-Message "========================================" "Cyan"

# Inicializar TLS 1.2
Enable-Tls12

# Ejecutar todas las actualizaciones
try {
    Update-RuckZuckApps
    Update-WingetApps
    Update-WindowsStoreApps
    Update-Drivers
} catch {
    Log-Message "Error crítico durante las actualizaciones: $($_.Exception.Message)" "Red"
} finally {
    # Flush final del buffer de logs
    Flush-LogBuffer

    Log-Message "========================================" "Green"
    Log-Message "  Proceso de actualización finalizado" "Green"
    Log-Message "========================================" "Green"

    # Liberar memoria
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}
