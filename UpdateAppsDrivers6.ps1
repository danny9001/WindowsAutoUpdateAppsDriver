#requires -Version 5.1
<#
.SYNOPSIS
  Actualiza apps (RuckZuck, WinGet, Microsoft Store) y Windows/Drivers.
  Compatible con Windows PowerShell 5.1 y PowerShell 7+. Preferible PS 7+.

.NOTES
  - Si se ejecuta en PS < 7, intentará relanzar en pwsh.exe (configurable).
  - En Windows Server se omiten tareas de Microsoft Store.
#>

[CmdletBinding()]
param(
    [switch]$NoRelaunch
)

# -------------------------
# Utilidades base
# -------------------------
function Write-Info($msg)    { Write-Host $msg -ForegroundColor Cyan }
function Write-Ok($msg)      { Write-Host $msg -ForegroundColor Green }
function Write-WarnMsg($msg) { Write-Host $msg -ForegroundColor Yellow }
function Write-ErrMsg($msg)  { Write-Host $msg -ForegroundColor Red }

# Forzar TLS 1.2 en Windows PowerShell 5.1
function Set-Tls12Enable {
    try {
        if ($PSVersionTable.PSVersion.Major -lt 7) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
    } catch { }
}

# Chequeo de admin (algunas tareas lo requieren)
function Test-IsAdmin {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = New-Object Security.Principal.WindowsPrincipal($wi)
    return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Internet robusto: pruebas HTTP/HTTPS (con proxy por defecto) + fallback TCP 443
function Test-Internet {
    param(
        [int]$TimeoutMs = 5000,
        [switch]$VerboseMode
    )

    Set-Tls12Enable

    # Intentar usar proxy del sistema con credenciales por defecto (útil en dominios)
    try {
        [System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()
        [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    } catch {}

    $probes = @(
        # NCSI / ConnectTest: pueden estar bloqueados en redes corporativas, probamos igual
        @{ Uri='http://www.msftconnecttest.com/connecttest.txt'; Expect='Microsoft Connect Test'; Method='GET'  },
        @{ Uri='http://www.msftncsi.com/ncsi.txt';             Expect='Microsoft NCSI';        Method='GET'  },
        # HTTPS HEAD a dominios de Microsoft (aceptamos 2xx/3xx)
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
            continue
        }
    }

    # Último recurso: prueba TCP 443 (no HTTP)
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect('www.microsoft.com', 443, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $client.EndConnect($iar); $client.Close()
            return $true
        } else {
            $client.Close()
        }
    } catch {
        if ($VerboseMode) {
            Write-Host ("[Test-Internet] Falló TCP 443: {0}" -f $_.Exception.Message) -ForegroundColor DarkYellow
        }
    }

    return $false
}

# Detectar/Relanzar en PowerShell 7 si estamos en 5.1 (por defecto relanza)
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
        if ($PSBoundParameters.ContainsKey('NoRelaunch') -and $NoRelaunch) {
            $argsToPass += '-NoRelaunch'
        }
        if ($PSCommandPath) {
            Start-Process -FilePath $pwshCmd -ArgumentList @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"") + $argsToPass -Wait
        } else {
            Start-Process -FilePath $pwshCmd -ArgumentList @('-NoLogo','-NoProfile') -Wait
        }
        exit
    } else {
        Write-WarnMsg "⚠️ No se encontró pwsh.exe. Continuando en Windows PowerShell con compatibilidad."
        return $false
    }
}

# Detectar si es Server (ProductType 1=Workstation, 2=DC, 3=Server)
function Get-IsServer {
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        return ($os.ProductType -ne 1)
    } catch {
        # Fallback si CIM no está disponible por alguna razón
        try {
            $os = Get-WmiObject Win32_OperatingSystem
            return ($os.ProductType -ne 1)
        } catch { return $false }
    }
}

# -------------------------
# RuckZuck (RZGet)
# -------------------------
# Descarga última versión estable sin tener que conocer la tag
$Global:RZGetDownloadUrlLatest = 'https://github.com/rzander/ruckzuck/releases/latest/download/RZGet.exe'

function Get-LatestRZGetVersion {
    Set-Tls12Enable
    try {
        $headers = @{
            'User-Agent' = 'RuckZuck-Updater'
            'Accept'     = 'application/vnd.github+json'
        }
        $api = 'https://api.github.com/repos/rzander/ruckzuck/releases/latest'
        $latest = Invoke-RestMethod -Uri $api -Headers $headers -ErrorAction Stop
        return $latest.tag_name
    } catch {
        return $null
    }
}

function Update-RuckZuckApps {
    $rzPath = Join-Path $PSScriptRoot 'RZGet.exe'
    if (!(Test-Path $rzPath)) {
        Write-WarnMsg "📥 RZGet.exe no encontrado. Descargando la última versión..."
        if (-not (Test-Internet -VerboseMode)) { Write-ErrMsg "❌ Sin Internet. No puedo descargar RZGet."; return }
        Set-Tls12Enable
        try {
            $iwrParams = @{ Uri = $Global:RZGetDownloadUrlLatest; OutFile = $rzPath; ErrorAction='Stop' }
            if ($PSVersionTable.PSVersion.Major -lt 7) { $iwrParams.UseBasicParsing = $true }
            Invoke-WebRequest @iwrParams
            Write-Ok "✅ RZGet.exe descargado."
        } catch {
            Write-ErrMsg "❌ Error al descargar RZGet: $($_.Exception.Message)"
            return
        }
    }

    Write-Info "🔍 Verificando aplicaciones con actualizaciones disponibles mediante RZGet..."
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

            Write-Ok "✅ Actualización RZGet completada. Aplicaciones actualizadas:"
            $updatesArray | ForEach-Object { Write-Host " - $_" -ForegroundColor White }
        } else {
            Write-Ok "✅ No se detectaron entradas parseables; puede que no haya actualizaciones."
        }
    } catch {
        Write-ErrMsg "❌ Error al verificar/actualizar con RZGet: $($_.Exception.Message)"
    }
}

# -------------------------
# WinGet
# -------------------------
function Ensure-WinGetSources {
    try {
        Write-Info "🔄 Actualizando/Restableciendo fuentes de WinGet..."
        winget source update --disable-interactivity | Out-Null
        # Restablece fuentes por defecto (winget + msstore)
        winget source reset --disable-interactivity | Out-Null
    } catch {
        Write-WarnMsg "⚠️ No se pudieron actualizar/restablecer las fuentes de WinGet: $($_.Exception.Message)"
    }
}

function Get-WinGetUpgradesList {
    param([switch]$AsTextFallback)

    try {
        $json = winget upgrade --accept-source-agreements --include-unknown --output json --disable-interactivity 2>$null
        if ([string]::IsNullOrWhiteSpace($json)) { throw "Salida JSON vacía" }
        $data = $json | ConvertFrom-Json -ErrorAction Stop
        # Winget puede devolver 'Upgrades' o lista plana
        if ($data.PSObject.Properties.Name -contains 'Upgrades') {
            return $data.Upgrades
        } elseif ($data -is [System.Collections.IEnumerable]) {
            return $data
        } else {
            return @()
        }
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
        Write-ErrMsg "❌ WinGet no está instalado. Omitiendo."
        return
    }
    # Permitir que winget pruebe conectividad si las sondas HTTP fallan
    $internet = Test-Internet -VerboseMode
    if (-not $internet) {
        Write-WarnMsg "⚠️ Sondas HTTP fallaron; probando comando 'winget source list' como verificación directa..."
        try { winget source list --disable-interactivity | Out-Null; $internet = $true } catch { }
    }
    if (-not $internet) {
        Write-ErrMsg "❌ Sin Internet. Omitiendo WinGet."
        return
    }

    Ensure-WinGetSources

    try {
        $upgrades = Get-WinGetUpgradesList -AsTextFallback
        if (-not $upgrades -or $upgrades.Count -eq 0) {
            Write-Ok "✅ No hay actualizaciones WinGet disponibles."
            return
        }

        Write-WarnMsg "✨ Aplicaciones con actualización (WinGet):"
        if ($upgrades -is [System.Collections.IEnumerable] -and $upgrades -and $upgrades[0].PSObject.Properties.Name -contains 'Package' ) {
            $upgrades | ForEach-Object { Write-Host (" - " + ($_?.Package?.Name ?? $_?.PackageIdentifier)) -ForegroundColor White }
        } else {
            $upgrades | ForEach-Object { Write-Host (" - " + $_) -ForegroundColor White }
        }

        Write-Info "🔄 Ejecutando 'winget upgrade --all' (incluye pinned y versiones desconocidas)..."
        winget upgrade --all --include-unknown --include-pinned --accept-package-agreements --accept-source-agreements --silent --disable-interactivity

        Write-Ok "✅ Actualización WinGet completada."
    } catch {
        Write-ErrMsg "❌ Error en actualización con WinGet: $($_.Exception.Message)"
    }
}

# -------------------------
# Microsoft Store
# -------------------------
function Update-MicrosoftStore {
    Write-Info "=== Actualizando apps de Microsoft Store... ==="

    if (Get-IsServer) {
        Write-WarnMsg "ℹ️ Equipo tipo Server: se omite Microsoft Store."
        return
    }

    $storeApp = Get-AppxPackage -Name Microsoft.WindowsStore -ErrorAction SilentlyContinue
    if (-not $storeApp) {
        Write-ErrMsg "❌ Microsoft Store no está instalada en este sistema."
        return
    }
    if (-not (Test-Internet -VerboseMode)) {
        Write-ErrMsg "❌ Sin Internet. Omitiendo Store."
        return
    }

    try {
        # Limpieza de caché con wsreset
        $wsresetPath = "C:\Windows\System32\wsreset.exe"
        if (Test-Path $wsresetPath) {
            Write-WarnMsg "🔄 Limpiando caché de Microsoft Store (wsreset)..."
            Start-Process -FilePath $wsresetPath -NoNewWindow -Wait
        } else {
            Write-WarnMsg "⚠️ wsreset.exe no encontrado; continúo sin limpieza."
        }

        # Asegurar fuente msstore en WinGet y actualizar
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Ensure-WinGetSources
            Write-Info "🔄 Actualizando apps Store vía WinGet (fuente msstore)..."
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

    if (-not (Test-Internet -VerboseMode)) {
        Write-ErrMsg "❌ Sin Internet. Abortando Windows Update."
        return
    }

    # Reinicio de servicios base
    $services = @("wuauserv","cryptsvc")
    Write-WarnMsg "🔄 Reiniciando servicios de Windows Update..."
    foreach ($s in $services) {
        try {
            Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
            Start-Service -Name $s -ErrorAction Stop
            Write-Ok "✅ Servicio $s reiniciado."
        } catch {
            Write-WarnMsg "⚠️ No se pudo reiniciar ${s}: $($_.Exception.Message)"
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

    if (Get-PendingReboot) {
        Write-WarnMsg "⚠️ Se requiere reiniciar el sistema para aplicar cambios."
    } else {
        Write-Ok "✅ No es necesario reiniciar."
    }
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
# Main
# -------------------------
$AutoRelaunchToPwsh = -not $NoRelaunch
if ($AutoRelaunchToPwsh) { Ensure-PowerShell7 -NoRelaunch:$NoRelaunch | Out-Null }

Write-Info "Iniciando actualizaciones automáticas de aplicaciones y del sistema..."
if (-not (Test-IsAdmin)) {
    Write-WarnMsg "ℹ️ Sugerencia: ejecuta como Administrador para mejores resultados (servicios, WU, etc.)."
}

Update-RuckZuckApps
Update-WinGetApps
Update-MicrosoftStore
Update-WindowsDriversAndUpdates

Write-Ok "✅ Proceso finalizado."
