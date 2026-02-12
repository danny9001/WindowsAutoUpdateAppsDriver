<#
.SYNOPSIS
    Script avanzado para buscar y descargar drivers automáticamente
    
.DESCRIPTION
    Versión avanzada que incluye descarga automática de drivers desde
    Windows Update, búsqueda inteligente y actualización masiva de drivers.
    
.PARAMETER DownloadPath
    Ruta donde se guardarán los drivers
    
.PARAMETER AutoDownload
    Descarga automática de drivers disponibles
    
.PARAMETER InstallDrivers
    Instala los drivers descargados automáticamente
    
.PARAMETER UpdateAllDrivers
    Intenta actualizar todos los drivers del sistema
    
.EXAMPLE
    .\Advanced-DriverDownloader.ps1 -DownloadPath "C:\Drivers"
    
.EXAMPLE
    .\Advanced-DriverDownloader.ps1 -AutoDownload -InstallDrivers
    
.NOTES
    Author: DIMA LTDA - Tecnología e Innovación
    Date: 2025-01-16
    Version: 2.0
    Requires: Elevated privileges for installation
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$DownloadPath = "$env:USERPROFILE\Downloads\Drivers",
    
    [Parameter(Mandatory=$false)]
    [switch]$AutoDownload,
    
    [Parameter(Mandatory=$false)]
    [switch]$InstallDrivers,
    
    [Parameter(Mandatory=$false)]
    [switch]$UpdateAllDrivers,
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateBackup
)

# Verificar privilegios de administrador
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($InstallDrivers -and -not $isAdmin) {
    Write-Host "❌ Este script requiere privilegios de administrador para instalar drivers" -ForegroundColor Red
    Write-Host "Por favor, ejecuta PowerShell como Administrador" -ForegroundColor Yellow
    exit 1
}

# Funciones de logging
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Debug')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch($Level) {
        'Info' { 'Cyan' }
        'Warning' { 'Yellow' }
        'Error' { 'Red' }
        'Success' { 'Green' }
        'Debug' { 'Gray' }
    }
    
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
    Write-Host "[$Level] " -NoNewline -ForegroundColor $color
    Write-Host $Message
    
    $logFile = Join-Path $DownloadPath "advanced_driver_log.txt"
    "[$timestamp] [$Level] $Message" | Out-File -FilePath $logFile -Append -Encoding UTF8
}

# Función para obtener drivers disponibles via Windows Update
function Get-WindowsUpdateDrivers {
    Write-Log "Buscando drivers en Windows Update..." -Level Info
    
    try {
        # Usar Microsoft Update en lugar de solo Windows Update
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        
        # Configurar para buscar drivers
        $updateSearcher.ServerSelection = 2  # Microsoft Update
        $updateSearcher.IncludePotentiallySupersededUpdates = $false
        
        Write-Log "Realizando búsqueda en Microsoft Update..." -Level Debug
        
        # Buscar solo drivers
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Driver'")
        
        $drivers = @()
        foreach ($update in $searchResult.Updates) {
            $drivers += [PSCustomObject]@{
                Title = $update.Title
                Description = $update.Description
                DriverClass = $update.DriverClass
                DriverHardwareID = $update.DriverHardwareID
                DriverManufacturer = $update.DriverManufacturer
                DriverModel = $update.DriverModel
                DriverProvider = $update.DriverProvider
                DriverVerDate = $update.DriverVerDate
                Size = [math]::Round($update.MaxDownloadSize / 1MB, 2)
                IsDownloaded = $update.IsDownloaded
                Update = $update
            }
        }
        
        Write-Log "Se encontraron $($drivers.Count) drivers disponibles" -Level Success
        return $drivers
        
    } catch {
        Write-Log "Error al buscar en Windows Update: $_" -Level Error
        return @()
    }
}

# Función para descargar drivers desde Windows Update
function Download-WindowsUpdateDriver {
    param(
        [Parameter(Mandatory=$true)]
        $DriverUpdate,
        
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath
    )
    
    try {
        Write-Log "Descargando: $($DriverUpdate.Title)" -Level Info
        
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateDownloader = $updateSession.CreateUpdateDownloader()
        
        $updateCollection = New-Object -ComObject Microsoft.Update.UpdateColl
        $updateCollection.Add($DriverUpdate.Update) | Out-Null
        
        $updateDownloader.Updates = $updateCollection
        $downloadResult = $updateDownloader.Download()
        
        if ($downloadResult.ResultCode -eq 2) {
            Write-Log "Driver descargado exitosamente: $($DriverUpdate.Title)" -Level Success
            return $true
        } else {
            Write-Log "Error al descargar driver. Código: $($downloadResult.ResultCode)" -Level Error
            return $false
        }
        
    } catch {
        Write-Log "Excepción al descargar driver: $_" -Level Error
        return $false
    }
}

# Función para instalar drivers descargados
function Install-DownloadedDriver {
    param(
        [Parameter(Mandatory=$true)]
        $DriverUpdate
    )
    
    try {
        Write-Log "Instalando: $($DriverUpdate.Title)" -Level Info
        
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateInstaller = $updateSession.CreateUpdateInstaller()
        
        $updateCollection = New-Object -ComObject Microsoft.Update.UpdateColl
        $updateCollection.Add($DriverUpdate.Update) | Out-Null
        
        $updateInstaller.Updates = $updateCollection
        $installResult = $updateInstaller.Install()
        
        if ($installResult.ResultCode -eq 2) {
            Write-Log "Driver instalado exitosamente" -Level Success
            return $true
        } else {
            Write-Log "Error al instalar driver. Código: $($installResult.ResultCode)" -Level Error
            return $false
        }
        
    } catch {
        Write-Log "Excepción al instalar driver: $_" -Level Error
        return $false
    }
}

# Función para obtener información detallada de drivers actuales
function Get-InstalledDriverInfo {
    Write-Log "Obteniendo información de drivers instalados..." -Level Info
    
    $drivers = Get-WmiObject Win32_PnPSignedDriver | Select-Object -Property `
        DeviceName,
        DriverVersion,
        DriverDate,
        Manufacturer,
        InfName,
        DriverProviderName,
        HardWareID,
        DeviceClass
    
    return $drivers
}

# Función para crear backup de drivers actuales
function Backup-CurrentDrivers {
    param(
        [string]$BackupPath
    )
    
    Write-Log "Creando backup de drivers actuales..." -Level Info
    
    try {
        $backupFolder = Join-Path $BackupPath "Driver_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null
        
        # Exportar drivers usando DISM
        $exportPath = Join-Path $backupFolder "DriverExport"
        Write-Log "Ejecutando DISM para exportar drivers..." -Level Debug
        
        $dismResult = dism /online /export-driver /destination:$exportPath
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Backup de drivers creado en: $backupFolder" -Level Success
            
            # Crear inventario de drivers exportados
            Get-InstalledDriverInfo | Export-Csv -Path (Join-Path $backupFolder "driver_inventory.csv") -NoTypeInformation -Encoding UTF8
            
            return $backupFolder
        } else {
            Write-Log "Error al crear backup con DISM" -Level Error
            return $null
        }
        
    } catch {
        Write-Log "Error al crear backup: $_" -Level Error
        return $null
    }
}

# Función para actualizar drivers usando PnPUtil
function Update-DriverWithPnPUtil {
    param(
        [string]$InfPath
    )
    
    try {
        Write-Log "Instalando driver desde: $InfPath" -Level Info
        
        $result = pnputil /add-driver $InfPath /install
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Driver instalado correctamente con PnPUtil" -Level Success
            return $true
        } else {
            Write-Log "Error al instalar con PnPUtil. Código: $LASTEXITCODE" -Level Error
            return $false
        }
        
    } catch {
        Write-Log "Excepción con PnPUtil: $_" -Level Error
        return $false
    }
}

# Función para verificar drivers desactualizados
function Get-OutdatedDrivers {
    Write-Log "Verificando drivers desactualizados..." -Level Info
    
    $outdated = @()
    $allDrivers = Get-InstalledDriverInfo
    
    foreach ($driver in $allDrivers) {
        if ($driver.DriverDate) {
            $driverAge = (Get-Date) - [DateTime]$driver.DriverDate
            
            # Considerar desactualizado si tiene más de 2 años
            if ($driverAge.TotalDays -gt 730) {
                $outdated += $driver
            }
        }
    }
    
    Write-Log "Se encontraron $($outdated.Count) drivers con más de 2 años" -Level Warning
    return $outdated
}

# Función para generar reporte detallado
function Export-DetailedReport {
    param(
        [array]$WUDrivers,
        [array]$InstalledDrivers,
        [array]$OutdatedDrivers,
        [hashtable]$Stats
    )
    
    $reportPath = Join-Path $DownloadPath "Detailed_Driver_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Reporte Detallado de Drivers - DIMA LTDA</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); overflow: hidden; }
        .header { background: linear-gradient(135deg, #0066cc 0%, #0052a3 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 30px; background: #f8f9fa; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }
        .stat-number { font-size: 3em; font-weight: bold; color: #0066cc; }
        .stat-label { color: #666; margin-top: 5px; }
        .section { padding: 30px; }
        .section h2 { color: #333; border-bottom: 3px solid #0066cc; padding-bottom: 10px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th { background: #0066cc; color: white; padding: 15px; text-align: left; font-weight: 600; }
        td { padding: 12px 15px; border-bottom: 1px solid #e0e0e0; }
        tr:hover { background-color: #f5f5f5; }
        .badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 0.85em; font-weight: 600; }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-warning { background: #fff3cd; color: #856404; }
        .badge-danger { background: #f8d7da; color: #721c24; }
        .badge-info { background: #d1ecf1; color: #0c5460; }
        .footer { background: #333; color: white; padding: 20px; text-align: center; }
        .progress-bar { width: 100%; height: 8px; background: #e0e0e0; border-radius: 4px; overflow: hidden; margin: 10px 0; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #0066cc, #00a8ff); transition: width 0.3s; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 Reporte Completo de Drivers</h1>
            <p>DIMA LTDA - Tecnología e Innovación</p>
            <p style="margin-top:10px; opacity:0.9;">Generado: $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">$($Stats.TotalInstalled)</div>
                <div class="stat-label">Drivers Instalados</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$($Stats.AvailableUpdates)</div>
                <div class="stat-label">Actualizaciones Disponibles</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$($Stats.OutdatedDrivers)</div>
                <div class="stat-label">Drivers Desactualizados</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$($Stats.Downloaded)</div>
                <div class="stat-label">Descargados</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$($Stats.Installed)</div>
                <div class="stat-label">Instalados</div>
            </div>
        </div>
        
        <div class="section">
            <h2>📥 Drivers Disponibles en Windows Update</h2>
            $(if ($WUDrivers.Count -gt 0) {
                "<table>
                    <tr>
                        <th>Driver</th>
                        <th>Fabricante</th>
                        <th>Versión</th>
                        <th>Tamaño (MB)</th>
                        <th>Estado</th>
                    </tr>"
                foreach ($driver in $WUDrivers) {
                    $statusBadge = if ($driver.IsDownloaded) { 
                        "<span class='badge badge-success'>Descargado</span>" 
                    } else { 
                        "<span class='badge badge-info'>Disponible</span>" 
                    }
                    "<tr>
                        <td>$($driver.Title)</td>
                        <td>$($driver.DriverManufacturer)</td>
                        <td>$($driver.DriverModel)</td>
                        <td>$($driver.Size)</td>
                        <td>$statusBadge</td>
                    </tr>"
                }
                "</table>"
            } else {
                "<p style='color:#666; padding:20px; text-align:center;'>✅ No hay actualizaciones disponibles en Windows Update</p>"
            })
        </div>
        
        <div class="section">
            <h2>⚠️ Drivers Desactualizados (>2 años)</h2>
            $(if ($OutdatedDrivers.Count -gt 0) {
                "<table>
                    <tr>
                        <th>Dispositivo</th>
                        <th>Fabricante</th>
                        <th>Versión</th>
                        <th>Fecha</th>
                        <th>Antigüedad</th>
                    </tr>"
                foreach ($driver in $OutdatedDrivers) {
                    $age = ((Get-Date) - [DateTime]$driver.DriverDate).Days
                    $ageYears = [math]::Round($age / 365, 1)
                    "<tr>
                        <td>$($driver.DeviceName)</td>
                        <td>$($driver.Manufacturer)</td>
                        <td>$($driver.DriverVersion)</td>
                        <td>$($driver.DriverDate)</td>
                        <td><span class='badge badge-warning'>$ageYears años</span></td>
                    </tr>"
                }
                "</table>"
            } else {
                "<p style='color:#666; padding:20px; text-align:center;'>✅ Todos los drivers están relativamente actualizados</p>"
            })
        </div>
        
        <div class="footer">
            <p><strong>DIMA LTDA - Tecnología e Innovación</strong></p>
            <p style="margin-top:10px; opacity:0.8;">Sistema automatizado de gestión de drivers</p>
        </div>
    </div>
</body>
</html>
"@
    
    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Log "Reporte detallado generado: $reportPath" -Level Success
    
    return $reportPath
}

# ========================================
# SCRIPT PRINCIPAL
# ========================================

try {
    # Banner
    Clear-Host
    Write-Host "`n"
    Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                               ║" -ForegroundColor Cyan
    Write-Host "║    GESTOR AVANZADO DE DRIVERS - DIMA LTDA                     ║" -ForegroundColor White
    Write-Host "║    Versión 2.0 - Búsqueda y Descarga Automática              ║" -ForegroundColor White
    Write-Host "║                                                               ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "`n"
    
    # Crear directorio
    if (-not (Test-Path $DownloadPath)) {
        New-Item -Path $DownloadPath -ItemType Directory -Force | Out-Null
    }
    
    # Estadísticas
    $stats = @{
        TotalInstalled = 0
        AvailableUpdates = 0
        OutdatedDrivers = 0
        Downloaded = 0
        Installed = 0
    }
    
    # 1. Backup si se solicita
    if ($CreateBackup) {
        Write-Host "💾 Creando backup de drivers actuales..." -ForegroundColor Yellow
        $backupPath = Backup-CurrentDrivers -BackupPath $DownloadPath
        if ($backupPath) {
            Write-Host "✅ Backup creado: $backupPath" -ForegroundColor Green
        }
    }
    
    # 2. Obtener drivers instalados
    Write-Host "`n📋 Analizando drivers instalados..." -ForegroundColor Yellow
    $installedDrivers = Get-InstalledDriverInfo
    $stats.TotalInstalled = $installedDrivers.Count
    Write-Host "✅ Total de drivers instalados: $($stats.TotalInstalled)" -ForegroundColor Green
    
    # 3. Verificar drivers desactualizados
    Write-Host "`n⏰ Verificando drivers desactualizados..." -ForegroundColor Yellow
    $outdatedDrivers = Get-OutdatedDrivers
    $stats.OutdatedDrivers = $outdatedDrivers.Count
    
    if ($outdatedDrivers.Count -gt 0) {
        Write-Host "⚠️  Se encontraron $($outdatedDrivers.Count) drivers con más de 2 años:" -ForegroundColor Yellow
        $outdatedDrivers | Select-Object -First 5 DeviceName, Manufacturer, DriverDate | Format-Table -AutoSize
    }
    
    # 4. Buscar actualizaciones en Windows Update
    Write-Host "`n🔍 Buscando actualizaciones en Windows Update..." -ForegroundColor Yellow
    $wuDrivers = Get-WindowsUpdateDrivers
    $stats.AvailableUpdates = $wuDrivers.Count
    
    if ($wuDrivers.Count -gt 0) {
        Write-Host "✅ Se encontraron $($wuDrivers.Count) actualizaciones de drivers disponibles" -ForegroundColor Green
        
        # Mostrar lista
        Write-Host "`nDrivers disponibles:" -ForegroundColor Cyan
        for ($i = 0; $i -lt [Math]::Min(10, $wuDrivers.Count); $i++) {
            Write-Host "   [$($i+1)] $($wuDrivers[$i].Title) - $($wuDrivers[$i].Size) MB" -ForegroundColor White
        }
        
        # Descargar si se solicita
        if ($AutoDownload) {
            Write-Host "`n📥 Descargando drivers..." -ForegroundColor Yellow
            
            foreach ($driver in $wuDrivers) {
                if (Download-WindowsUpdateDriver -DriverUpdate $driver -DestinationPath $DownloadPath) {
                    $stats.Downloaded++
                    
                    # Instalar si se solicita
                    if ($InstallDrivers) {
                        if (Install-DownloadedDriver -DriverUpdate $driver) {
                            $stats.Installed++
                        }
                    }
                }
                
                # Mostrar progreso
                $progress = [math]::Round(($stats.Downloaded / $wuDrivers.Count) * 100)
                Write-Progress -Activity "Procesando drivers" -Status "$progress% completado" -PercentComplete $progress
            }
            
            Write-Progress -Activity "Procesando drivers" -Completed
            Write-Host "✅ Descarga completada: $($stats.Downloaded) de $($wuDrivers.Count)" -ForegroundColor Green
            
            if ($InstallDrivers) {
                Write-Host "✅ Instalación completada: $($stats.Installed) de $($stats.Downloaded)" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "✅ No hay actualizaciones de drivers disponibles" -ForegroundColor Green
    }
    
    # 5. Generar reporte
    Write-Host "`n📄 Generando reporte detallado..." -ForegroundColor Yellow
    $reportPath = Export-DetailedReport -WUDrivers $wuDrivers -InstalledDrivers $installedDrivers -OutdatedDrivers $outdatedDrivers -Stats $stats
    
    # Resumen final
    Write-Host "`n"
    Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                 ✅ PROCESO COMPLETADO                          ║" -ForegroundColor White
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host "`n"
    Write-Host "📊 Resumen de operaciones:" -ForegroundColor Cyan
    Write-Host "   • Drivers instalados: $($stats.TotalInstalled)" -ForegroundColor White
    Write-Host "   • Actualizaciones disponibles: $($stats.AvailableUpdates)" -ForegroundColor White
    Write-Host "   • Drivers desactualizados: $($stats.OutdatedDrivers)" -ForegroundColor White
    Write-Host "   • Drivers descargados: $($stats.Downloaded)" -ForegroundColor White
    Write-Host "   • Drivers instalados: $($stats.Installed)" -ForegroundColor White
    Write-Host "`n📁 Archivos generados:" -ForegroundColor Cyan
    Write-Host "   • Reporte: $reportPath" -ForegroundColor White
    Write-Host "   • Log: $(Join-Path $DownloadPath 'advanced_driver_log.txt')" -ForegroundColor White
    Write-Host "`n"
    
    # Abrir reporte
    $openReport = Read-Host "¿Deseas abrir el reporte HTML? (S/N)"
    if ($openReport -eq 'S' -or $openReport -eq 's') {
        Start-Process $reportPath
    }
    
    # Mensaje de reinicio si se instalaron drivers
    if ($stats.Installed -gt 0) {
        Write-Host "`n⚠️  Se instalaron $($stats.Installed) drivers. Se recomienda reiniciar el sistema." -ForegroundColor Yellow
        $reboot = Read-Host "¿Deseas reiniciar ahora? (S/N)"
        if ($reboot -eq 'S' -or $reboot -eq 's') {
            Write-Host "🔄 Reiniciando en 10 segundos..." -ForegroundColor Yellow
            shutdown /r /t 10 /c "Reinicio programado después de instalación de drivers"
        }
    }
    
} catch {
    Write-Log "Error crítico: $_" -Level Error
    Write-Host "`n❌ Error crítico: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}