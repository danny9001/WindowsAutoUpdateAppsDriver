#requires -Version 5.1
<#
.SYNOPSIS
  Actualiza apps (RuckZuck, WinGet, Microsoft Store) y Windows/Drivers.
  Compatible con Windows PowerShell 5.1 y PowerShell 7+. Preferible PS 7+.

.PARAMETER NoRelaunch
  No relanzar en pwsh aunque PS sea < 7.

.PARAMETER AutoInstallPwsh
  Si PS < 7 y no hay pwsh, descargar e instalar automáticamente PowerShell 7 (MSI) y relanzar el script.

.PARAMETER SkipStore
  Omitir pasos de Microsoft Store incluso en equipos cliente.

.PARAMETER OutputFolder
  Carpeta para descargas y logs (por defecto, carpeta del script).

.NOTES
  - En Windows Server se omiten tareas de Microsoft Store.
  - Requiere privilegios de admin para partes de Windows Update e instalación de PS7.

.PowerShell Excecution
  - Set-ExecutionPolicy Unrestricted -Scope Process -Force
  - Set-ExecutionPolicy Unrestricted
#>

[CmdletBinding()]
param(
    [switch]$NoRelaunch,
    [switch]$AutoInstallPwsh,
    [switch]$SkipStore,
    [string]$OutputFolder = $(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path })
)

# -------------------------
# Utilidades base y logging
# -------------------------
function Write-Info($msg)    { Write-Host $msg -ForegroundColor Cyan }
function Write-Ok($msg)      { Write-Host $msg -ForegroundColor Green }
function Write-WarnMsg($msg) { Write-Host $msg -ForegroundColor Yellow }
function Write-ErrMsg($msg)  { Write-Host $msg -ForegroundColor Red }

# Asegurar carpeta de trabajo
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}
# Transcript
$tsFile = Join-Path $OutputFolder ("Actualizar-{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $tsFile -ErrorAction SilentlyContinue | Out-Null } catch {}

# TLS 1.2 en Windows PowerShell 5.1
function Set-Tls12Enable {
    try {
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
    } catch { }
}

# Usar proxy del sistema + credenciales de red por defecto
function Set-ProxyDefaults {
    try {
        [System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()
        [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    } catch { }
}

# Admin
function Test-IsAdmin {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = New-Object Security.Principal.WindowsPrincipal($wi)
    return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Internet robusto: HTTP/HTTPS + fallback TCP 443
function Test-Internet {
    param(
        [int]$TimeoutMs = 5000,
        [switch]$VerboseMode
    )
    Set-Tls12Enable
    Set-ProxyDefaults

    $probes = @(
        @{ Uri='http://www.msftconnecttest.com/connecttest.txt'; Expect='Microsoft Connect Test'; Method='GET'  },
        @{ Uri='http://www.msftncsi.com/ncsi.txt';             Expect='Microsoft NCSI';        Method='GET'  },
        @{ Uri='https://www.microsoft.com';                     Expect=$null;                  Method='HEAD' },
        @{ Uri='https://www.bing.com';                          Expect=$null;                  Method='HEAD' }
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
        } catch {
            if ($VerboseMode) {
                Write-Host ("[Test-Internet] Falló {0}: {1}" -f $p.Uri, $_.Exception.Message) -ForegroundColor DarkYellow
            }
        }
    }

    # Fallback TCP 443
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect('www.microsoft.com', 443, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { $client.EndConnect($iar); $client.Close(); return $true }
        $client.Close()
    } catch {
        if ($VerboseMode) {
            Write-Host ("[Test-Internet] Falló TCP 443: {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
        }
    }
    return $false
}

# Detectar/Relanzar en PowerShell 7 si estamos en 5.1
function Ensure-PowerShell7 {
    param([switch]$NoRelaunch)
    if ($PSVersionTable.PSVersion.Major -ge 7) { return $true }

    Write-WarnMsg "⚠️ Detectado Windows PowerShell $($PSVersionTable.PSVersion). Se recomienda PowerShell 7 o superior."
    if ($NoRelaunch) { return $false }

    # Buscar pwsh.exe
    $pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
    if (-not $pwshCmd) {
        $candidate = Join-Path $Env:ProgramFiles 'PowerShell\7\pwsh.exe'
        if (Test-Path $candidate) { $pwshCmd = $candidate }
    }
    if ($pwshCmd) {
        Write-Info "🔁 Reejecutando este script en PowerShell 7..."
        $argsToPass = @()
        if ($PSBoundParameters.ContainsKey('NoRelaunch') -and $NoRelaunch) { $argsToPass += '-NoRelaunch' }
        if ($PSBoundParameters.ContainsKey('AutoInstallPwsh') -and $AutoInstallPwsh) { $argsToPass += '-AutoInstallPwsh' }
        if ($PSBoundParameters.ContainsKey('SkipStore') -and $SkipStore) { $argsToPass += '-SkipStore' }
        $argsToPass += @('-OutputFolder',"`"$OutputFolder`"")

        if ($PSCommandPath) {
            Start-Process -FilePath $pwshCmd -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"") + $argsToPass -Wait
        } else {
            Start-Process -FilePath $pwshCmd -ArgumentList @('-NoLogo','-NoProfile') -Wait
        }
        exit
    } else {
        return $false
    }
}

# Instalar PowerShell 7 (MSI estable) si hace falta y tenemos permiso
function Install-PowerShell7 {
    if ($PSVersionTable.PSVersion.Major -ge 7) { return $true }
    if (Get-Command pwsh -ErrorAction SilentlyContinue) { return $true }
    if (-not (Test-IsAdmin)) { Write-ErrMsg "❌ Se requiere Admin para instalar PowerShell 7."; return $false }

    if (-not (Test-Internet -VerboseMode)) { Write-ErrMsg "❌ Sin Internet para descargar PowerShell 7."; return $false }

    Set-Tls12Enable; Set-ProxyDefaults
    # Detectar arquitectura
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
    $arch = Get-OSArch
    $headers = @{
        'User-Agent' = 'Pwsh-Bootstrapper'
        'Accept'     = 'application/vnd.github+json'
    }
    $api = 'https://api.github.com/repos/PowerShell/PowerShell/releases/latest'
    try {
        Write-Info "📥 Buscando última release estable de PowerShell 7 ($arch)..."
        $rel = Invoke-RestMethod -Uri $api -Headers $headers -ErrorAction Stop
        $assets = @($rel.assets)
        $pattern = switch ($arch) {
            'x64'   { 'PowerShell-.*-win-x64\.msi$' }
            'x86'   { 'PowerShell-.*-win-x86\.msi$' }
            'arm64' { 'PowerShell-.*-win-arm64\.msi$' }
            default { 'PowerShell-.*-win-x64\.msi$' }
        }
        $asset = $assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
        if (-not $asset) { throw "No se halló MSI para $arch." }
        $msiPath = Join-Path $OutputFolder $asset.name
        Write-Info "⬇️ Descargando $($asset.name)..."
        $iwr = @{ Uri = $asset.browser_download_url; OutFile = $msiPath; ErrorAction = 'Stop' }
        if ($PSVersionTable.PSVersion.Major -lt 7) { $iwr.UseBasicParsing = $true }
        Invoke-WebRequest @iwr
        Write-Info "⚙️ Instalando PowerShell 7 (silencioso)..."
        Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /qn /norestart" -Wait
        Start-Sleep -Seconds 3
        if (Get-Command pwsh -ErrorAction SilentlyContinue) {
            Write-Ok "✅ PowerShell 7 instalado."
            return $true
        } else {
            Write-ErrMsg "❌ Instalación de PowerShell 7 no verificada."
            return $false
        }
    } catch {
        Write-ErrMsg "❌ Error instalando PowerShell 7: $($_.Exception.Message)"
        return $false
    }
}

# Detectar si es Server (ProductType 1=Workstation, 2=DC, 3=Server)
function Get-IsServer {
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        return ($os.ProductType -ne 1)
    } catch {
        try {
            $os = Get-WmiObject Win32_OperatingSystem
            return ($os.ProductType -ne 1)
        } catch { return $false }
    }
}

# -------------------------
# RuckZuck (RZGet)
# -------------------------
$Global:RZGetLatestUrl = 'https://github.com/rzander/ruckzuck/releases/latest/download/RZGet.exe'  # latest estable

function Download-RZGet {
    param([string]$DestinationFolder = $OutputFolder)
    $dest = Join-Path $DestinationFolder 'RZGet.exe'
    if (Test-Path $dest) { return $dest }
    Write-Info "📥 Descargando RZGet.exe (RuckZuck)..."
    Set-Tls12Enable; Set-ProxyDefaults
    $iwrParams = @{ Uri = $Global:RZGetLatestUrl; OutFile = $dest; ErrorAction='Stop' }
    if ($PSVersionTable.PSVersion.Major -lt 7) { $iwrParams.UseBasicParsing = $true }
    Invoke-WebRequest @iwrParams
    Write-Ok "✅ RZGet.exe descargado en: $dest"
    return $dest
}

function Update-RuckZuckApps {
    $rzPath = Download-RZGet
    if (-not $rzPath) {
        Write-ErrMsg "❌ No se pudo obtener RZGet.exe."
        return
    }
    if (-not (Test-Internet -VerboseMode)) {
        Write-ErrMsg "❌ Sin Internet. Omitiendo RZGet."
        return
    }
    Write-Info "🔍 Consultando actualizaciones (RZGet)..."
    try {
        $updatesList = & $rzPath update --list --all --user 2>&1
        if ($updatesList -match 'No updates available') {
            Write-Ok "✅ No hay actualizaciones pendientes por RZGet."
            return
        }
        $updatesArray = $updatesList -split "`n" | Where-Object { $_ -match "^\s*\- " } | ForEach-Object { $_ -replace "^\s*\- ", "" }
        if ($updatesArray.Count -gt 0) {
            Write-WarnMsg "✨ Actualizaciones disponibles (RZGet):"
            $updatesArray | ForEach-Object { Write-Host " - $_" -ForegroundColor White }
            Write-Info "🔄 Iniciando actualización con RZGet..."
            & $rzPath update --all --retry --user
            Write-Ok "✅ Actualización RZGet completada."
        } else {
            Write-Ok "✅ Sin actualizaciones detectadas por RZGet."
        }
    } catch {
        Write-ErrMsg "❌ Error RZGet: $($_.Exception.Message)"
    }
}

# -------------------------
# WinGet
# -------------------------
function Ensure-WinGetSources {
    try {
        Write-Info "🔄 Actualizando/Restableciendo fuentes de WinGet..."
        winget source update --disable-interactivity | Out-Null
        winget source reset  --disable-interactivity | Out-Null  # restablece winget + msstore
    } catch {
        Write-WarnMsg "⚠️ No se pudieron preparar las fuentes de WinGet: $($_.Exception.Message)"
    }
}

function Get-WinGetUpgradesList {
    param([switch]$AsTextFallback)
    try {
        $json = winget upgrade --accept-source-agreements --include-unknown --output json --disable-interactivity 2>$null
        if ([string]::IsNullOrWhiteSpace($json)) { throw "Salida JSON vacía" }
        $data = $json | ConvertFrom-Json -ErrorAction Stop
        if ($data.PSObject.Properties.Name -contains 'Upgrades') { return $data.Upgrades }
        elseif ($data -is [System.Collections.IEnumerable]) { return $data }
        else { return @() }
    } catch {
        if ($AsTextFallback) {
            $text = winget upgrade --accept-source-agreements --include-unknown --disable-interactivity | Out-String
            $lines = $text -split "`n" | Where-Object { $_ -match '^\S' }
            return $lines
        } else { throw }
    }
}

function Update-WinGetApps {
    Write-Info "=== Actualizando aplicaciones con WinGet... ==="
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-ErrMsg "❌ WinGet no está instalado o disponible en este sistema. Omitiendo."
        return
    }
    $internet = Test-Internet -VerboseMode
    if (-not $internet) {
        Write-WarnMsg "⚠️ Sondas HTTP fallaron; pruebo 'winget source list' para confirmar conectividad..."
        try { winget source list --disable-interactivity | Out-Null; $internet = $true } catch { }
    }
    if (-not $internet) { Write-ErrMsg "❌ Sin Internet. Omitiendo WinGet."; return }

    Ensure-WinGetSources
    try {
        $upgrades = Get-WinGetUpgradesList -AsTextFallback
        if (-not $upgrades -or $upgrades.Count -eq 0) { Write-Ok "✅ No hay actualizaciones WinGet disponibles."; return }

        Write-WarnMsg "✨ Aplicaciones con actualización (WinGet):"
        if ($upgrades -and $upgrades[0].PSObject.Properties.Name -contains 'Package') {
            $upgrades | ForEach-Object { Write-Host (" - " + (${_}.Package.Name ?? ${_}.PackageIdentifier)) -ForegroundColor White }
        } else {
            $upgrades | ForEach-Object { Write-Host (" - " + $_) -ForegroundColor White }
        }

        Write-Info "🔄 'winget upgrade --all' (incluye pinned y versiones desconocidas)..."
        winget upgrade --all --include-unknown --include-pinned --accept-package-agreements --accept-source-agreements --silent --disable-interactivity
        Write-Ok "✅ Actualización WinGet completada."
    } catch {
        Write-ErrMsg "❌ Error en WinGet: $($_.Exception.Message)"
    }
}

# -------------------------
# Microsoft Store
# -------------------------
function Update-MicrosoftStore {
    Write-Info "=== Actualizando apps de Microsoft Store... ==="
    if ($SkipStore) { Write-WarnMsg "ℹ️ Se solicitó omitir Microsoft Store."; return }
    if (Get-IsServer) { Write-WarnMsg "ℹ️ Equipo tipo Server: se omite Microsoft Store."; return }

    $storeApp = Get-AppxPackage -Name Microsoft.WindowsStore -ErrorAction SilentlyContinue
    if (-not $storeApp) { Write-ErrMsg "❌ Microsoft Store no está instalada en este sistema."; return }
    if (-not (Test-Internet -VerboseMode)) { Write-ErrMsg "❌ Sin Internet. Omitiendo Store."; return }

    try {
        $wsresetPath = "C:\Windows\System32\wsreset.exe"
        if (Test-Path $wsresetPath) {
            Write-WarnMsg "🔄 Limpiando caché de Microsoft Store (wsreset)..."
            Start-Process -FilePath $wsresetPath -NoNewWindow -Wait
        } else {
            Write-WarnMsg "⚠️ wsreset.exe no encontrado; continúo sin limpieza."
        }

        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Ensure-WinGetSources
            Write-Info "🔄 Actualizando apps Store vía WinGet (msstore)..."
            winget upgrade --source msstore --all --include-unknown --accept-package-agreements --accept-source-agreements --silent --disable-interactivity
        } else {
            Write-WarnMsg "⚠️ WinGet no está presente; solo se ejecutó wsreset."
        }
        Write-Ok "✅ Proceso de Microsoft Store finalizado."
    } catch {
        Write-ErrMsg "❌ Error en Microsoft Store: $($_.Exception.Message)"
    }
}

# -------------------------
# Windows Update (drivers + parches)
# -------------------------
function Ensure-NuGetProvider {
    try {
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Write-Info "📥 Instalando proveedor NuGet para PowerShellGet..."
            Install-PackageProvider -Name NuGet -Scope CurrentUser -Force -ErrorAction Stop | Out-Null
        }
    } catch {
        Write-WarnMsg "⚠️ No se pudo instalar el proveedor NuGet: $($_.Exception.Message)"
    }
}

function Update-WindowsDriversAndUpdates {
    Write-Info "=== Iniciando Windows Update (sistema y drivers)... ==="
    if (-not (Test-IsAdmin)) { Write-WarnMsg "ℹ️ Ejecuta como Administrador para aplicar Windows Update sin restricciones."; }
    if (-not (Test-Internet -VerboseMode)) { Write-ErrMsg "❌ Sin Internet. Abortando Windows Update."; return }

    # Reinicio de servicios base
    $services = @("wuauserv","cryptsvc")
    Write-WarnMsg "🔄 Reiniciando servicios de Windows Update..."
    foreach ($s in $services) {
        try {
            Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
            Start-Service -Name $s -ErrorAction Stop
            Write-Ok ("✅ Servicio {0} reiniciado." -f ${s})
        } catch {
            Write-WarnMsg ("⚠️ No se pudo reiniciar {0}: {1}" -f ${s}, $_.Exception.Message)
        }
    }

    # PSWindowsUpdate
    try {
        Ensure-NuGetProvider
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-WarnMsg "📥 Instalando módulo PSWindowsUpdate..."
            Install-Module PSWindowsUpdate -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        }
        Import-Module PSWindowsUpdate -ErrorAction Stop
        Write-Info "🔍 Buscando e instalando actualizaciones..."
        Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -IgnoreReboot | Out-Null
        Write-Ok "✅ Actualizaciones instaladas correctamente."
    } catch {
        Write-ErrMsg "❌ Error con PSWindowsUpdate: $($_.Exception.Message)"
    }

    if (Get-PendingReboot) { Write-WarnMsg "⚠️ Se requiere reiniciar el sistema para aplicar cambios." }
    else { Write-Ok "✅ No es necesario reiniciar." }
}

# Chequeo de reinicio pendiente
function Get-PendingReboot {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations'
    )
    foreach ($k in $keys) { if (Test-Path $k) { return $true } }
    return $false
}

# -------------------------
# MAIN
# -------------------------
Write-Info "Iniciando actualizaciones automáticas de aplicaciones y del sistema..."
Write-Host (" - PowerShell:  {0}" -f $PSVersionTable.PSVersion)
Write-Host (" - Admin:       {0}" -f $(if (Test-IsAdmin) { 'Sí' } else { 'No' }))
Write-Host (" - Carpeta log: {0}" -f $OutputFolder)

# Si PS < 7, intentar relanzar o instalar (según switches)
$needPwsh = ($PSVersionTable.PSVersion.Major -lt 7)
if ($needPwsh) {
    $relaunched = Ensure-PowerShell7 -NoRelaunch:$NoRelaunch
    if (-not $relaunched -and $AutoInstallPwsh) {
        if (Install-PowerShell7) {
            # Relanzar ahora que está instalado
            Ensure-PowerShell7 | Out-Null
        } else {
            Write-WarnMsg "⚠️ Continuando en Windows PowerShell 5.1 (compatibilidad reducida)."
        }
    }
}

# Aviso de privilegios
if (-not (Test-IsAdmin)) {
    Write-WarnMsg "ℹ️ Sugerencia: ejecuta como Administrador para mejores resultados (servicios, WU, instalación de PS7...)."
}

# Flujo de actualización
Update-RuckZuckApps
Update-WinGetApps
Update-MicrosoftStore
Update-WindowsDriversAndUpdates

Write-Ok "✅ Proceso finalizado."
try { Stop-Transcript | Out-Null } catch {}

