#requires -Version 5.1
<#
.SYNOPSIS
  Actualiza apps (RuckZuck, WinGet, Microsoft Store) y Windows/Drivers.
  Instala automaticamente WinGet y sus dependencias si no estan disponibles.
  Compatible con Windows PowerShell 5.1 y PowerShell 7+.

.PARAMETER NoRelaunch
  No relanzar en pwsh aunque PS sea < 7.

.PARAMETER AutoInstallPwsh
  Si PS < 7 y no hay pwsh, instalar automaticamente PowerShell 7 y relanzar.

.PARAMETER SkipStore
  Omitir pasos de Microsoft Store incluso en equipos cliente.

.PARAMETER ForceWinGetReinstall
  Forzar reinstalacion de WinGet aunque este instalado.

.PARAMETER OutputFolder
  Carpeta para descargas y logs (por defecto, carpeta del script).

.NOTES
  v8.0 - Combinacion de UpdateAppsDrivers + Reinstalar-WinGet
  - Instala VC++ Redistributable automaticamente si falta
  - Instala WinGet y dependencias automaticamente si faltan
  - En Windows Server se omiten tareas de Microsoft Store
  - Requiere privilegios de admin para WinGet install y Windows Update
#>

[CmdletBinding()]
param(
    [switch]$NoRelaunch,
    [switch]$AutoInstallPwsh,
    [switch]$SkipStore,
    [switch]$ForceWinGetReinstall,
    [string]$OutputFolder = $(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path })
)

#region Configuracion inicial
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
#endregion

#region Utilidades base y logging
function Write-Info($msg)    { Write-Host $msg -ForegroundColor Cyan }
function Write-Ok($msg)      { Write-Host $msg -ForegroundColor Green }
function Write-WarnMsg($msg) { Write-Host $msg -ForegroundColor Yellow }
function Write-ErrMsg($msg)  { Write-Host $msg -ForegroundColor Red }
function Write-Step($step, $total, $msg) { Write-Host "[$step/$total] $msg" -ForegroundColor Yellow }

if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}

$tsFile = Join-Path $OutputFolder ("Actualizar-{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $tsFile -ErrorAction SilentlyContinue | Out-Null } catch {}
#endregion

#region Funciones de red y sistema
function Set-Tls12Enable {
    try {
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
    } catch { }
}

function Set-ProxyDefaults {
    try {
        [System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()
        [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    } catch { }
}

function Test-IsAdmin {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = New-Object Security.Principal.WindowsPrincipal($wi)
    return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Internet {
    param([int]$TimeoutMs = 5000)
    Set-Tls12Enable
    Set-ProxyDefaults

    $probes = @(
        @{ Uri='http://www.msftconnecttest.com/connecttest.txt'; Expect='Microsoft Connect Test'; Method='GET' },
        @{ Uri='https://www.microsoft.com'; Expect=$null; Method='HEAD' }
    )

    foreach ($p in $probes) {
        try {
            $params = @{
                Uri         = $p.Uri
                Method      = $p.Method
                TimeoutSec  = [math]::Ceiling($TimeoutMs/1000.0)
                ErrorAction = 'Stop'
            }
            if ($PSVersionTable.PSVersion.Major -lt 7) { $params.UseBasicParsing = $true }
            $resp = Invoke-WebRequest @params
            if ($p.Expect) {
                if ($resp.Content -match [regex]::Escape($p.Expect)) { return $true }
            } else {
                if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 400) { return $true }
            }
        } catch { }
    }

    # Fallback TCP 443
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect('www.microsoft.com', 443, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $client.EndConnect($iar)
            $client.Close()
            return $true
        }
        $client.Close()
    } catch { }
    return $false
}

function Get-IsServer {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        return ($os.ProductType -ne 1)
    } catch {
        return $false
    }
}

function Get-OSArch {
    try {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            return [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLower()
        } else {
            $pa = $env:PROCESSOR_ARCHITECTURE
            if ($pa -match 'ARM64') { return 'arm64' }
            elseif ([Environment]::Is64BitOperatingSystem) { return 'x64' }
            else { return 'x86' }
        }
    } catch { return 'x64' }
}
#endregion

#region PowerShell 7
function Ensure-PowerShell7 {
    param([switch]$NoRelaunch)
    if ($PSVersionTable.PSVersion.Major -ge 7) { return $true }

    Write-WarnMsg "Detectado Windows PowerShell $($PSVersionTable.PSVersion). Se recomienda PowerShell 7+."
    if ($NoRelaunch) { return $false }

    $pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
    if (-not $pwshCmd) {
        $candidate = Join-Path $Env:ProgramFiles 'PowerShell\7\pwsh.exe'
        if (Test-Path $candidate) { $pwshCmd = $candidate }
    }
    if ($pwshCmd) {
        Write-Info "Reejecutando en PowerShell 7..."
        $argsToPass = @()
        if ($NoRelaunch) { $argsToPass += '-NoRelaunch' }
        if ($AutoInstallPwsh) { $argsToPass += '-AutoInstallPwsh' }
        if ($SkipStore) { $argsToPass += '-SkipStore' }
        if ($ForceWinGetReinstall) { $argsToPass += '-ForceWinGetReinstall' }
        $argsToPass += @('-OutputFolder', "`"$OutputFolder`"")

        if ($PSCommandPath) {
            Start-Process -FilePath $pwshCmd -ArgumentList (@('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"") + $argsToPass) -Wait
        }
        exit
    }
    return $false
}

function Install-PowerShell7 {
    if ($PSVersionTable.PSVersion.Major -ge 7) { return $true }
    if (Get-Command pwsh -ErrorAction SilentlyContinue) { return $true }
    if (-not (Test-IsAdmin)) { Write-ErrMsg "Se requiere Admin para instalar PowerShell 7."; return $false }
    if (-not (Test-Internet)) { Write-ErrMsg "Sin Internet para descargar PowerShell 7."; return $false }

    Set-Tls12Enable; Set-ProxyDefaults
    $arch = Get-OSArch
    $headers = @{ 'User-Agent' = 'Pwsh-Bootstrapper'; 'Accept' = 'application/vnd.github+json' }

    try {
        Write-Info "Buscando ultima release de PowerShell 7 ($arch)..."
        $rel = Invoke-RestMethod -Uri 'https://api.github.com/repos/PowerShell/PowerShell/releases/latest' -Headers $headers -ErrorAction Stop
        $pattern = switch ($arch) {
            'x64'   { 'PowerShell-.*-win-x64\.msi$' }
            'x86'   { 'PowerShell-.*-win-x86\.msi$' }
            'arm64' { 'PowerShell-.*-win-arm64\.msi$' }
            default { 'PowerShell-.*-win-x64\.msi$' }
        }
        $asset = $rel.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
        if (-not $asset) { throw "No se hallo MSI para $arch." }

        $msiPath = Join-Path $OutputFolder $asset.name
        Write-Info "Descargando $($asset.name)..."
        $iwr = @{ Uri = $asset.browser_download_url; OutFile = $msiPath; ErrorAction = 'Stop' }
        if ($PSVersionTable.PSVersion.Major -lt 7) { $iwr.UseBasicParsing = $true }
        Invoke-WebRequest @iwr

        Write-Info "Instalando PowerShell 7..."
        Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /qn /norestart" -Wait
        Start-Sleep -Seconds 3

        if (Get-Command pwsh -ErrorAction SilentlyContinue) {
            Write-Ok "PowerShell 7 instalado."
            return $true
        }
        Write-ErrMsg "Instalacion de PowerShell 7 no verificada."
        return $false
    } catch {
        Write-ErrMsg "Error instalando PowerShell 7: $($_.Exception.Message)"
        return $false
    }
}
#endregion

#region VC++ Redistributable
function Test-VCRedistInstalled {
    $vcKey = 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64'
    if (Test-Path $vcKey) { return $true }
    if (Test-Path 'C:\Windows\System32\MSVCP140.dll') { return $true }
    return $false
}

function Install-VCRedist {
    if (Test-VCRedistInstalled) {
        Write-Ok "VC++ Redistributable ya instalado."
        return $true
    }

    if (-not (Test-IsAdmin)) {
        Write-WarnMsg "Se requiere Admin para instalar VC++ Redistributable."
        return $false
    }

    Write-Info "Instalando Visual C++ Redistributable 2015-2022..."
    $tempVC = Join-Path $env:TEMP 'VCRedist'
    New-Item -ItemType Directory -Path $tempVC -Force | Out-Null

    try {
        $arch = Get-OSArch
        $vcUrl = switch ($arch) {
            'x64'   { 'https://aka.ms/vs/17/release/vc_redist.x64.exe' }
            'x86'   { 'https://aka.ms/vs/17/release/vc_redist.x86.exe' }
            'arm64' { 'https://aka.ms/vs/17/release/vc_redist.arm64.exe' }
            default { 'https://aka.ms/vs/17/release/vc_redist.x64.exe' }
        }

        $vcPath = Join-Path $tempVC "vc_redist.$arch.exe"
        Write-Info "Descargando VC++ Redistributable ($arch)..."
        $iwr = @{ Uri = $vcUrl; OutFile = $vcPath; ErrorAction = 'Stop' }
        if ($PSVersionTable.PSVersion.Major -lt 7) { $iwr.UseBasicParsing = $true }
        Invoke-WebRequest @iwr

        Write-Info "Ejecutando instalador..."
        Start-Process -FilePath $vcPath -ArgumentList '/install', '/quiet', '/norestart' -Wait

        Remove-Item $tempVC -Recurse -Force -ErrorAction SilentlyContinue

        if (Test-VCRedistInstalled) {
            Write-Ok "VC++ Redistributable instalado correctamente."
            return $true
        }
        Write-WarnMsg "No se pudo verificar la instalacion de VC++."
        return $false
    } catch {
        Write-ErrMsg "Error instalando VC++ Redistributable: $($_.Exception.Message)"
        Remove-Item $tempVC -Recurse -Force -ErrorAction SilentlyContinue
        return $false
    }
}
#endregion

#region WinGet Installation
function Test-WinGetInstalled {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        try {
            $version = & winget --version 2>$null
            if ($LASTEXITCODE -eq 0 -and $version) { return $true }
        } catch { }
    }

    # Verificar ruta alternativa
    if (Test-Path 'C:\WinGet\winget.exe') {
        try {
            $version = & 'C:\WinGet\winget.exe' --version 2>$null
            if ($LASTEXITCODE -eq 0) { return $true }
        } catch { }
    }
    return $false
}

function Install-WinGet {
    Write-Info "========================================"
    Write-Info "  INSTALACION DE WINGET Y DEPENDENCIAS"
    Write-Info "========================================"

    if (-not (Test-IsAdmin)) {
        Write-ErrMsg "Se requiere ejecutar como Administrador para instalar WinGet."
        return $false
    }

    if (-not (Test-Internet)) {
        Write-ErrMsg "Sin conexion a Internet."
        return $false
    }

    # Paso 1: Instalar VC++ si falta
    Write-Step 1 5 "Verificando Visual C++ Redistributable..."
    Install-VCRedist | Out-Null

    # Paso 2: Limpiar instalaciones previas
    Write-Step 2 5 "Limpiando instalaciones previas..."
    Get-AppxPackage -Name Microsoft.DesktopAppInstaller -AllUsers -ErrorAction SilentlyContinue | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue

    if (Test-Path 'C:\WinGet') {
        Remove-Item 'C:\WinGet' -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Paso 3: Descargar componentes
    Write-Step 3 5 "Descargando componentes de WinGet..."
    $tempFolder = Join-Path $env:TEMP 'WinGetInstall'
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    try {
        Set-Tls12Enable; Set-ProxyDefaults

        # VCLibs
        Write-Info "  Descargando VCLibs..."
        $vclibsPath = Join-Path $tempFolder 'VCLibs.appx'
        Invoke-WebRequest -Uri 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx' -OutFile $vclibsPath -UseBasicParsing

        # UI.Xaml
        Write-Info "  Descargando UI.Xaml..."
        $uixamlPath = Join-Path $tempFolder 'UIXaml.appx'
        Invoke-WebRequest -Uri 'https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.8.6/Microsoft.UI.Xaml.2.8.x64.appx' -OutFile $uixamlPath -UseBasicParsing

        # WinGet
        Write-Info "  Descargando WinGet..."
        $latestRelease = Invoke-RestMethod -Uri 'https://api.github.com/repos/microsoft/winget-cli/releases/latest' -Headers @{'User-Agent'='WinGet-Installer'}
        $wingetUrl = ($latestRelease.assets | Where-Object { $_.name -like '*.msixbundle' }).browser_download_url
        $licenseUrl = ($latestRelease.assets | Where-Object { $_.name -like '*License1.xml' }).browser_download_url

        $wingetPath = Join-Path $tempFolder 'WinGet.msixbundle'
        $licensePath = Join-Path $tempFolder 'License.xml'

        Invoke-WebRequest -Uri $wingetUrl -OutFile $wingetPath -UseBasicParsing
        Invoke-WebRequest -Uri $licenseUrl -OutFile $licensePath -UseBasicParsing

        # Paso 4: Instalar dependencias y WinGet
        Write-Step 4 5 "Instalando paquetes AppX..."

        Write-Info "  Instalando VCLibs..."
        Add-AppxPackage -Path $vclibsPath -ErrorAction SilentlyContinue

        Write-Info "  Instalando UI.Xaml..."
        Add-AppxPackage -Path $uixamlPath -ErrorAction SilentlyContinue

        Write-Info "  Instalando WinGet..."
        Add-AppxProvisionedPackage -Online -PackagePath $wingetPath -LicensePath $licensePath -ErrorAction SilentlyContinue | Out-Null
        Add-AppxPackage -Path $wingetPath -ErrorAction SilentlyContinue

        # Paso 5: Configurar acceso permanente
        Write-Step 5 5 "Configurando acceso permanente..."
        Start-Sleep -Seconds 3

        $wingetPackage = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue
        if ($wingetPackage) {
            $wingetSource = $wingetPackage.InstallLocation
            $wingetDest = 'C:\WinGet'

            New-Item -ItemType Directory -Path $wingetDest -Force | Out-Null
            Copy-Item -Path "$wingetSource\*" -Destination $wingetDest -Recurse -Force -ErrorAction SilentlyContinue

            # Configurar PATH
            $currentPath = [Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::Machine)
            if ($currentPath -notlike "*$wingetDest*") {
                [Environment]::SetEnvironmentVariable('Path', "$currentPath;$wingetDest", [EnvironmentVariableTarget]::Machine)
                $env:Path = "$env:Path;$wingetDest"
            }

            # Permisos
            icacls $wingetDest /grant 'Users:(OI)(CI)RX' /T 2>$null | Out-Null
        }

        # Limpiar
        Remove-Item $tempFolder -Recurse -Force -ErrorAction SilentlyContinue

        # Verificar
        Start-Sleep -Seconds 2
        if (Test-WinGetInstalled) {
            Write-Ok "WinGet instalado correctamente."
            return $true
        }

        Write-ErrMsg "No se pudo verificar la instalacion de WinGet."
        return $false

    } catch {
        Write-ErrMsg "Error instalando WinGet: $($_.Exception.Message)"
        Remove-Item $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
        return $false
    }
}
#endregion

#region RuckZuck
$Global:RZGetLatestUrl = 'https://github.com/rzander/ruckzuck/releases/latest/download/RZGet.exe'

function Download-RZGet {
    param([string]$DestinationFolder = $OutputFolder)
    $dest = Join-Path $DestinationFolder 'RZGet.exe'
    if (Test-Path $dest) { return $dest }

    Write-Info "Descargando RZGet.exe..."
    Set-Tls12Enable; Set-ProxyDefaults
    $iwrParams = @{ Uri = $Global:RZGetLatestUrl; OutFile = $dest; ErrorAction='Stop' }
    if ($PSVersionTable.PSVersion.Major -lt 7) { $iwrParams.UseBasicParsing = $true }
    Invoke-WebRequest @iwrParams
    Write-Ok "RZGet.exe descargado."
    return $dest
}

function Update-RuckZuckApps {
    Write-Info "=== Actualizando con RuckZuck ==="

    $rzPath = Download-RZGet
    if (-not $rzPath -or -not (Test-Path $rzPath)) {
        Write-ErrMsg "No se pudo obtener RZGet.exe."
        return
    }

    if (-not (Test-Internet)) {
        Write-ErrMsg "Sin Internet. Omitiendo RZGet."
        return
    }

    try {
        $updatesList = & $rzPath update --list --all --user 2>&1
        if ($updatesList -match 'No updates available') {
            Write-Ok "No hay actualizaciones por RZGet."
            return
        }

        $updatesArray = $updatesList -split "`n" | Where-Object { $_ -match '^\s*\- ' } | ForEach-Object { $_ -replace '^\s*\- ', '' }
        if ($updatesArray.Count -gt 0) {
            Write-WarnMsg "Actualizaciones disponibles (RZGet):"
            $updatesArray | ForEach-Object { Write-Host " - $_" }
            Write-Info "Iniciando actualizacion..."
            & $rzPath update --all --retry --user
            Write-Ok "Actualizacion RZGet completada."
        } else {
            Write-Ok "Sin actualizaciones por RZGet."
        }
    } catch {
        Write-ErrMsg "Error RZGet: $($_.Exception.Message)"
    }
}
#endregion

#region WinGet Updates
function Ensure-WinGetSources {
    try {
        winget source update --disable-interactivity 2>$null | Out-Null
        winget source reset --disable-interactivity 2>$null | Out-Null
    } catch { }
}

function Update-WinGetApps {
    Write-Info "=== Actualizando con WinGet ==="

    # Verificar/instalar WinGet
    if (-not (Test-WinGetInstalled) -or $ForceWinGetReinstall) {
        Write-WarnMsg "WinGet no disponible o reinstalacion forzada."
        if (-not (Install-WinGet)) {
            Write-ErrMsg "No se pudo instalar WinGet. Omitiendo."
            return
        }
    }

    if (-not (Test-Internet)) {
        Write-ErrMsg "Sin Internet. Omitiendo WinGet."
        return
    }

    Ensure-WinGetSources

    try {
        Write-Info "Buscando actualizaciones..."
        $upgrades = winget upgrade --accept-source-agreements --include-unknown --disable-interactivity 2>$null

        if ($upgrades -match 'No installed package found matching') {
            Write-Ok "No hay actualizaciones WinGet disponibles."
            return
        }

        Write-Info "Ejecutando 'winget upgrade --all'..."
        winget upgrade --all --include-unknown --include-pinned --accept-package-agreements --accept-source-agreements --silent --disable-interactivity
        Write-Ok "Actualizacion WinGet completada."
    } catch {
        Write-ErrMsg "Error en WinGet: $($_.Exception.Message)"
    }
}
#endregion

#region Microsoft Store
function Update-MicrosoftStore {
    Write-Info "=== Actualizando Microsoft Store ==="

    if ($SkipStore) {
        Write-WarnMsg "Microsoft Store omitida por parametro."
        return
    }
    if (Get-IsServer) {
        Write-WarnMsg "Equipo Server: se omite Microsoft Store."
        return
    }

    $storeApp = Get-AppxPackage -Name Microsoft.WindowsStore -ErrorAction SilentlyContinue
    if (-not $storeApp) {
        Write-WarnMsg "Microsoft Store no instalada."
        return
    }

    if (-not (Test-Internet)) {
        Write-ErrMsg "Sin Internet. Omitiendo Store."
        return
    }

    try {
        $wsreset = 'C:\Windows\System32\wsreset.exe'
        if (Test-Path $wsreset) {
            Write-Info "Limpiando cache de Store..."
            Start-Process -FilePath $wsreset -NoNewWindow -Wait -ErrorAction SilentlyContinue
        }

        if (Test-WinGetInstalled) {
            Ensure-WinGetSources
            Write-Info "Actualizando apps Store via WinGet..."
            winget upgrade --source msstore --all --include-unknown --accept-package-agreements --accept-source-agreements --silent --disable-interactivity
        }
        Write-Ok "Proceso Microsoft Store finalizado."
    } catch {
        Write-ErrMsg "Error en Microsoft Store: $($_.Exception.Message)"
    }
}
#endregion

#region Windows Update
function Ensure-NuGetProvider {
    try {
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Write-Info "Instalando proveedor NuGet..."
            Install-PackageProvider -Name NuGet -Scope CurrentUser -Force -ErrorAction Stop | Out-Null
        }
    } catch { }
}

function Get-PendingReboot {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    )
    foreach ($k in $keys) { if (Test-Path $k) { return $true } }
    return $false
}

function Update-WindowsDriversAndUpdates {
    Write-Info "=== Windows Update (sistema y drivers) ==="

    if (-not (Test-IsAdmin)) {
        Write-WarnMsg "Ejecuta como Administrador para Windows Update completo."
    }
    if (-not (Test-Internet)) {
        Write-ErrMsg "Sin Internet. Abortando Windows Update."
        return
    }

    # Reinicio de servicios
    $services = @('wuauserv', 'cryptsvc')
    Write-Info "Reiniciando servicios de Windows Update..."
    foreach ($s in $services) {
        try {
            Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
            Start-Service -Name $s -ErrorAction SilentlyContinue
        } catch { }
    }

    # PSWindowsUpdate
    try {
        Ensure-NuGetProvider
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Info "Instalando modulo PSWindowsUpdate..."
            Install-Module PSWindowsUpdate -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        }
        Import-Module PSWindowsUpdate -ErrorAction Stop

        Write-Info "Buscando e instalando actualizaciones..."
        Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -IgnoreReboot -ErrorAction SilentlyContinue | Out-Null
        Write-Ok "Actualizaciones instaladas."
    } catch {
        Write-ErrMsg "Error con PSWindowsUpdate: $($_.Exception.Message)"
    }

    if (Get-PendingReboot) {
        Write-WarnMsg "Se requiere reiniciar el sistema."
    } else {
        Write-Ok "No es necesario reiniciar."
    }
}
#endregion

#region MAIN
Write-Info "========================================"
Write-Info "  ACTUALIZADOR DE APPS Y SISTEMA v8.0"
Write-Info "========================================"
Write-Host ""
Write-Host " PowerShell:  $($PSVersionTable.PSVersion)"
Write-Host " Admin:       $(if (Test-IsAdmin) { 'Si' } else { 'No' })"
Write-Host " Carpeta:     $OutputFolder"
Write-Host ""

# Verificar/instalar PS7
if ($PSVersionTable.PSVersion.Major -lt 7) {
    $relaunched = Ensure-PowerShell7 -NoRelaunch:$NoRelaunch
    if (-not $relaunched -and $AutoInstallPwsh) {
        if (Install-PowerShell7) {
            Ensure-PowerShell7 | Out-Null
        } else {
            Write-WarnMsg "Continuando en Windows PowerShell 5.1."
        }
    }
}

# Aviso de privilegios
if (-not (Test-IsAdmin)) {
    Write-WarnMsg "Sugerencia: ejecuta como Administrador para mejores resultados."
    Write-Host ""
}

# Verificar VC++ antes de todo
if (-not (Test-VCRedistInstalled)) {
    Write-WarnMsg "VC++ Redistributable no detectado. Instalando..."
    Install-VCRedist | Out-Null
}

# Flujo de actualizacion
Update-RuckZuckApps
Update-WinGetApps
Update-MicrosoftStore
Update-WindowsDriversAndUpdates

Write-Host ""
Write-Ok "========================================"
Write-Ok "  PROCESO FINALIZADO"
Write-Ok "========================================"
try { Stop-Transcript | Out-Null } catch {}
#endregion

# SIG # Begin signature block
# MIIcCwYJKoZIhvcNAQcCoIIb/DCCG/gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA2VbSCHhYjxsQU
# m+l2VEA21fy6fra/3x9O+InXPBSz46CCFlAwggMSMIIB+qADAgECAhATmDGpAnWb
# tErJFNrykwxMMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMMFkdlbmlhbC1JVCBD
# b2RlIFNpZ25pbmcwHhcNMjYwMTIzMTQyNzU4WhcNMzEwMTIzMTQzNzU2WjAhMR8w
# HQYDVQQDDBZHZW5pYWwtSVQgQ29kZSBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEF
# AAOCAQ8AMIIBCgKCAQEAs1YXDZNCHhSDQTA2vlSP9lXIRFUR6B1Cu9C15f+IK0pL
# lvgp6m/6dkJ/YfvizXAhmLAx5pTL0ldW/gVccnq3UWQ5oaV15HU85XAnHhDT0Dak
# vB2/lnsclkjkPSUGJpbR5USPnzUSVGgz4aO2MfgdELsS1dm0fzvjjkSVHP4zxjgS
# YBh6WPOTV9+uF3LXwjU7Sr7J1XLUECSd9COcpW7NkFWPT7tLTiI83MjrSZMEpIJM
# 7ZlEZCCpExEiZAlfmNpRpkcHqqni1cAO2aorDD0xC/6F3VtThUyWofyDgiVkQLZh
# HfpsOhxxYNc7tXehJwL77O9Xi+LzayX0ExJSq2GykQIDAQABo0YwRDAOBgNVHQ8B
# Af8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFBJwLjfjLH9r
# 7xOEa1Y3FDTPYvVeMA0GCSqGSIb3DQEBCwUAA4IBAQBrrYVnjjDu824HWppc2Jp3
# 4HOrLlLucog4yJ8K457USW3IA+kuxChMnF5nCIdIOlehrmlscjAA6g/XGAMutbXp
# N9d/ucJFbsKHANkra5sz+vHQlMifZLJxSuFZWkJrv2m3PWZ8g5ZvUjjPYt277iVe
# WPgZiRNWcAf5bEoYWjbUKJxAYojM2N5vWo4hn88yvegadFPY8K5ZTC9lQH5s5ZQq
# haruG0uUvvyFG/sDZ16gmTQT7TuWf0gowr49cwZUE38ZtlNzoDMBe04+KEJHkivO
# d68he6s6iKiFxzPpv4UK+RRshtvrikMFvIp48krgIv9zBxCR2c7SoBMirhW9vTGZ
# MIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0BAQwFADBl
# MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
# d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJv
# b3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7J
# IT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxS
# D1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb
# 7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1ef
# VFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoY
# OAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSa
# M0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI
# 8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9L
# BADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfm
# Q6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDr
# McXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15Gkv
# mB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
# FgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGL
# p6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEF
# BQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRw
# Oi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0Eu
# Y3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0G
# CSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzshV6p
# Grsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1W
# z/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp
# 8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++hUD38dglo
# hJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5xaiNrIv8S
# uFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGtDCCBJygAwIBAgIQ
# DcesVwX/IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEV
# MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
# MSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAw
# MDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0
# YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaD
# LFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1
# +JH7Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh
# /AS7sQRuQL37QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpL
# tlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8
# BbfnFRQVESYOszFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMv
# aB0WkE/2qHxJ0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL
# 6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/
# q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb
# 1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVF
# JfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MC
# AwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp
# 5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9P
# MA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcB
# AQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggr
# BgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+
# Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNq
# hCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd6ywFLery
# cvZTAz40y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26M
# HvVY9gCDA/JYsq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOczgj5kjat
# VB+NdADVZKON/gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPS
# egOOzr4EWj7PtspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI
# 7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4Y
# tL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/
# wyW4N7OigizwJWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch
# 28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQ
# D7yFylIz0scmbKvFoW2jNrbM1pD2T7m3XDCCBu0wggTVoAMCAQICEAqA7xhLjfEF
# gtHEdqeVdGgwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoT
# DkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRp
# bWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNTA2MDQwMDAw
# MDBaFw0zNjA5MDMyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQwOTYgVGlt
# ZXN0YW1wIFJlc3BvbmRlciAyMDI1IDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDQRqwtEsae0OquYFazK1e6b1H/hnAKAd/KN8wZQjBjMqiZ3xTWcfsL
# wOvRxUwXcGx8AUjni6bz52fGTfr6PHRNv6T7zsf1Y/E3IU8kgNkeECqVQ+3bzWYe
# sFtkepErvUSbf+EIYLkrLKd6qJnuzK8Vcn0DvbDMemQFoxQ2Dsw4vEjoT1FpS54d
# NApZfKY61HAldytxNM89PZXUP/5wWWURK+IfxiOg8W9lKMqzdIo7VA1R0V3Zp3Dj
# jANwqAf4lEkTlCDQ0/fKJLKLkzGBTpx6EYevvOi7XOc4zyh1uSqgr6UnbksIcFJq
# LbkIXIPbcNmA98Oskkkrvt6lPAw/p4oDSRZreiwB7x9ykrjS6GS3NR39iTTFS+EN
# TqW8m6THuOmHHjQNC3zbJ6nJ6SXiLSvw4Smz8U07hqF+8CTXaETkVWz0dVVZw7kn
# h1WZXOLHgDvundrAtuvz0D3T+dYaNcwafsVCGZKUhQPL1naFKBy1p6llN3QgshRt
# a6Eq4B40h5avMcpi54wm0i2ePZD5pPIssoszQyF4//3DoK2O65Uck5Wggn8O2klE
# TsJ7u8xEehGifgJYi+6I03UuT1j7FnrqVrOzaQoVJOeeStPeldYRNMmSF3voIgMF
# tNGh86w3ISHNm0IaadCKCkUe2LnwJKa8TIlwCUNVwppwn4D3/Pt5pwIDAQABo4IB
# lTCCAZEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU5Dv88jHt/f3X85FxYxlQQ89h
# jOgwHwYDVR0jBBgwFoAU729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQD
# AgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSBiDCBhTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAC
# hlFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRU
# aW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBU
# oFKgUIZOaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
# VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcw
# CAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAZSqt8Rwn
# BLmuYEHs0QhEnmNAciH45PYiT9s1i6UKtW+FERp8FgXRGQ/YAavXzWjZhY+hIfP2
# JkQ38U+wtJPBVBajYfrbIYG+Dui4I4PCvHpQuPqFgqp1PzC/ZRX4pvP/ciZmUnth
# fAEP1HShTrY+2DE5qjzvZs7JIIgt0GCFD9ktx0LxxtRQ7vllKluHWiKk6FxRPyUP
# xAAYH2Vy1lNM4kzekd8oEARzFAWgeW3az2xejEWLNN4eKGxDJ8WDl/FQUSntbjZ8
# 0FU3i54tpx5F/0Kr15zW/mJAxZMVBrTE2oi0fcI8VMbtoRAmaaslNXdCG1+lqvP4
# FbrQ6IwSBXkZagHLhFU9HCrG/syTRLLhAezu/3Lr00GrJzPQFnCEH1Y58678Igmf
# ORBPC1JKkYaEt2OdDh4GmO0/5cHelAK2/gTlQJINqDr6JfwyYHXSd+V08X1JUPvB
# 4ILfJdmL+66Gp3CSBXG6IwXMZUXBhtCyIaehr0XkBoDIGMUG1dUtwq1qmcwbdUfc
# SYCn+OwncVUXf53VJUNOaMWMts0VlRYxe5nK+At+DI96HAlXHAL5SlfYxJ7La54i
# 71McVWRP66bW+yERNpbJCjyCYG2j+bdpxo/1Cy4uPcU3AWVPGrbn5PhDBf3Frogu
# zzhk++ami+r3Qrx5bIbY3TVzgiFI7Gq3zWcxggURMIIFDQIBATA1MCExHzAdBgNV
# BAMMFkdlbmlhbC1JVCBDb2RlIFNpZ25pbmcCEBOYMakCdZu0SskU2vKTDEwwDQYJ
# YIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAvBgkqhkiG9w0BCQQxIgQgiiGL/1NLZhAAgEw5M6pZiZTCMqKnuax1WGnzUpZb
# n/QwDQYJKoZIhvcNAQEBBQAEggEANmfYwiWNhJu+pZ6HVEDr37OZ/Y2KWwXJIVUq
# l1fzr9Bm2lK1kEMTtcTh9gGpVzQxxGLIyAl7B98/oAp+XLOtaNpiAT/B/l4EuB2e
# L3B7Rp5rTFWZa/uV6/x8YWO68o2MImymDhNDqxbrZfkX9Iooy6E65XFt/MHqjwu/
# 5EMGgiMx3r7VGCpitVLeQg6rJysCantqPYaY2FKsBLa3CT51K8cMuL7UF4kGEdbF
# mfhEPbr/JZvhqzvn4OehLiHUS/TAGkPhtLM/NBXj5bNtf4fkLzp5IJIMg3QaRQUn
# cM8GfmcXQuN4QlhMzhthKfmSw4bXW/IT9wIfGjJVEndDOyjvwaGCAyYwggMiBgkq
# hkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHEdqeV
# dGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG
# CSqGSIb3DQEJBTEPFw0yNjAxMjMxNDQwMTFaMC8GCSqGSIb3DQEJBDEiBCAIO8DC
# nUFFRQsoExE+FWeCxPjEKNOng27L/0bgy5KLFDANBgkqhkiG9w0BAQEFAASCAgCf
# +3cZY7yIZJfK8tdnrAH8AF+UIoD+0ZFfbQaKg3r+5Dha7mHEx1ycjrBRsUq7cutR
# SpC4BLwsHL6nS2TLNKFBGf5QIm7Ne/LpelAhFwp77THsJkDnh84NTVnsgT3Hlfuk
# jSkFCeTGigneJ1ptKjDy9jdgQcUgrFH+VrKMK7geIc83IgJig2p7O6L0HVdy7NGt
# 02dYps5C/O32ke6jTtS46CCSgUcgnFmEVNrnY4guC/vrihN9mzxO/licDKspTu3K
# o6j6XCFFN6v+0VQyO3tnmJHl/Hn2atzQvXnuwvAhiQWuRIgvD9HB4nFXdBkvQhjh
# Dj14lfwkAjFvoG8g4BTce0+cRFp9kf78VQk3B3SDXjVRXLk2tlaW5MiNmQV+bNuf
# cPCsOffgCR94WZ30jxqmw4U07VJQ1TVEV6Cirw537WwzJ0JJH8OtVQz85BERYVkE
# HlOoAi3uHj1rDUhqejSTyGjhqhax+cTeUZr5P/U1C20W5QbUuX7tKMOSd6jTMsC4
# k2Web2QLhzxP1Oxdi7gRWQeAxPEZWc3I6pyRIT9QAHBi9mQD6yoCZMclRjqE1CQW
# iYTMw7jXbG7fy22al6ZgBuaqEqqu7bGvKueX0NkXqizVyM5B1Njl3fSkpVfGtAvV
# qO6VovANR0W8Q8HXxkDhEPXqPrZPIsAFguSs+Djk2Q==
# SIG # End signature block
