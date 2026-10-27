#requires -Version 5.1
<#
.SYNOPSIS
  Actualiza apps (RuckZuck, WinGet, Microsoft Store) y Windows/Drivers.
  Basado en el flujo probado de UpdateAppsDrivers7.1.ps1.
  Instala PowerShell 7 y WinGet cuando no estan disponibles (LTSC/Windows Server incluidos).

.PARAMETER NoRelaunch
  No relanzar en pwsh aunque PS sea < 7.

.PARAMETER SkipStore
  Omitir pasos de Microsoft Store incluso en equipos cliente.

.PARAMETER ForceWinGetReinstall
  Reinstalar WinGet aunque ya este disponible.

.PARAMETER ScheduledRun
  Uso interno de la tarea programada: omite preguntas e instala WinGet si falta.

.PARAMETER SkipScheduleTask
  No preguntar por la tarea programada.

.PARAMETER ReconfigureTask
  Permite cambiar el horario aunque la tarea ya exista (por defecto, si existe no se pregunta).

.PARAMETER IncludePinned
  Actualizar tambien paquetes WinGet anclados (pin). Por defecto se respetan.

.PARAMETER IncludeUnknown
  Incluir paquetes WinGet con version desconocida. Por defecto se omiten.

.PARAMETER AllowReinstall
  Permitir desinstalar + reinstalar cuando WinGet indica otra tecnologia de instalacion. Por defecto no.

.PARAMETER ExcludeIds
  Ids de WinGet a omitir (lista separada por comas). Tambien se lee 'exclusiones.txt' (un Id por linea) junto al script.

.PARAMETER RebootPolicy
  None (solo avisa) o IfPending (reinicia a los 60 s si queda reinicio pendiente).

.PARAMETER DryRun
  Solo lista lo pendiente (RZGet, WinGet, Windows Update); no instala ni cambia nada.

.PARAMETER LogRetentionDays
  Dias que se conservan los logs Actualizar-*.log (por defecto 30).

.PARAMETER OutputFolder
  Carpeta para descargas y logs (por defecto, carpeta del script).

.NOTES
  - Lee UpdateAppsDrivers8.1.config.json junto al script; lo crea sin preguntas si falta.
  - En Windows Server se omiten tareas de Microsoft Store.
  - Requiere privilegios de admin para partes de Windows Update e instalación de PS7.
#>

[CmdletBinding()]
param(
    [switch]$NoRelaunch,
    [switch]$SkipStore,
    [switch]$ForceWinGetReinstall,
    [switch]$ScheduledRun,
    [switch]$SkipScheduleTask,
    [switch]$ReconfigureTask,
    [switch]$IncludePinned,
    [switch]$IncludeUnknown,
    [switch]$AllowReinstall,
    [switch]$DryRun,
    [string[]]$ExcludeIds = @(),
    [ValidateSet('None','IfPending')][string]$RebootPolicy = 'None',
    [int]$LogRetentionDays = 30,
    [string]$OutputFolder = $(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path })
)

# Permite -ExcludeIds "a,b" (al pasar por -File llega como una sola cadena)
$ExcludeIds = @($ExcludeIds | ForEach-Object { $_ -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$script:Failures = [Collections.Generic.List[string]]::new()
$script:Successes = [Collections.Generic.List[string]]::new()
$script:Skipped = [Collections.Generic.List[string]]::new()
$script:InternetCheckedAt = $null
# Modo detallado: -Verbose o "Verbose": true en el JSON. Usa salida propia (Write-Diag) y silencia el
# -Verbose nativo, que llenaria la salida con mensajes internos de Import-Module, Get-CimInstance, etc.
$script:VerboseRequested = [bool]$PSBoundParameters['Verbose']
$script:DiagMode = $script:VerboseRequested
$VerbosePreference = 'SilentlyContinue'

# -------------------------
# Utilidades base y logging
# -------------------------
$script:UpdaterScriptPath = $PSCommandPath
function Write-Info($msg)    { Write-Host $msg -ForegroundColor Cyan }
function Write-Ok($msg)      { Write-Host $msg -ForegroundColor Green }
function Write-WarnMsg($msg) { Write-Host $msg -ForegroundColor Yellow }
function Write-ErrMsg($msg)  { Write-Host $msg -ForegroundColor Red }
function Write-Detail($msg)  { Write-Host "    $msg" -ForegroundColor DarkGray }
function Write-Diag($msg)    { if ($script:DiagMode) { Write-Host ("  [diag {0:HH:mm:ss}] {1}" -f (Get-Date), $msg) -ForegroundColor DarkGray } }
function Write-Section {
    param([int]$Number, [int]$Total, [string]$Title)
    $text = " [$Number/$Total] $Title "
    Write-Host ''
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
    Write-Host $text -ForegroundColor Cyan
    Write-Host ('═' * 70) -ForegroundColor DarkCyan
}

# Salida UTF-8 para leer bien la salida de winget (evita caracteres como "┬«")
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch {}

function Save-UpdaterConfiguration {
    $temporaryFile = "$($script:UpdaterConfigPath).$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $script:UpdaterConfig | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $temporaryFile -Encoding UTF8 -ErrorAction Stop
        Move-Item -LiteralPath $temporaryFile -Destination $script:UpdaterConfigPath -Force -ErrorAction Stop
    } finally {
        if (Test-Path -LiteralPath $temporaryFile) { Remove-Item -LiteralPath $temporaryFile -ErrorAction SilentlyContinue }
    }
}

function Initialize-UpdaterConfiguration {
    $script:UpdaterConfigPath = Join-Path (Split-Path -Parent $script:UpdaterScriptPath) 'UpdateAppsDrivers8.1.config.json'
    $script:UpdaterConfig = [pscustomobject]@{
        AskQuestions = $false
        SkipStore = $false
        SkipPackages = @()
        InstallWinGetIfMissing = $true
        Verbose = $false
        Schedule = [pscustomobject]@{ Enabled=$false; DayOfWeek='Sunday'; Time='22:00' }
        RuckZuck = [pscustomobject]@{ SkipShortNames=@(); DelayDays=0; ScanTimeoutSeconds=180; InstallTimeoutSeconds=1800; VersionCheckDays=7 }
        Drivers = [pscustomobject]@{ Sources=@('Oem','Intel','WindowsUpdate'); IncludeFirmware=$true; InstallVendorTool=$true; SkipIntelIds=@(); InstallTimeoutSeconds=3600 }
    }
    if (Test-Path -LiteralPath $script:UpdaterConfigPath) {
        try {
            $data = Get-Content -LiteralPath $script:UpdaterConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $data -or $data -isnot [pscustomobject]) { throw 'Se requiere un objeto JSON.' }
            foreach ($name in @('AskQuestions','SkipStore','InstallWinGetIfMissing','Verbose')) {
                if ($data.PSObject.Properties.Name -contains $name) {
                    if ($data.$name -isnot [bool]) { throw "$name debe ser true o false." }
                    $script:UpdaterConfig.$name = $data.$name
                }
            }
            if ($data.PSObject.Properties.Name -contains 'SkipPackages') {
                if ($data.SkipPackages -isnot [array]) { throw 'SkipPackages debe ser un arreglo JSON.' }
                foreach ($id in $data.SkipPackages) { if ($id -isnot [string] -or $id -notmatch '^[\w.\+\-]+$') { throw "ID omitido invalido: $id" } }
                $script:UpdaterConfig.SkipPackages = @($data.SkipPackages | Select-Object -Unique)
            }
            if ($data.PSObject.Properties.Name -contains 'Schedule') {
                if ($data.Schedule -isnot [pscustomobject]) { throw 'Schedule debe ser un objeto JSON.' }
                foreach ($name in @('Enabled','DayOfWeek','Time')) {
                    if ($data.Schedule.PSObject.Properties.Name -contains $name) { $script:UpdaterConfig.Schedule.$name = $data.Schedule.$name }
                }
            }
            if ($data.PSObject.Properties.Name -contains 'RuckZuck') {
                $rz = $data.RuckZuck
                if ($rz -isnot [pscustomobject]) { throw 'RuckZuck debe ser un objeto JSON.' }
                if ($rz.PSObject.Properties.Name -contains 'SkipShortNames') {
                    if ($rz.SkipShortNames -isnot [array]) { throw 'RuckZuck.SkipShortNames debe ser un arreglo.' }
                    foreach ($short in $rz.SkipShortNames) {
                        if ($short -isnot [string] -or $short -notmatch '^[\w.+\-]+$') { throw "ShortName omitido invalido: $short" }
                    }
                    $script:UpdaterConfig.RuckZuck.SkipShortNames = @($rz.SkipShortNames | Select-Object -Unique)
                }
                foreach ($setting in @(@('DelayDays',0,365),@('ScanTimeoutSeconds',10,3600),@('InstallTimeoutSeconds',30,14400),@('VersionCheckDays',1,90))) {
                    $name=$setting[0]
                    if ($rz.PSObject.Properties.Name -contains $name) {
                        $value=$rz.$name
                        if (($value -isnot [int] -and $value -isnot [long]) -or $value -lt $setting[1] -or $value -gt $setting[2]) { throw "RuckZuck.$name debe ser un entero entre $($setting[1]) y $($setting[2])." }
                        $script:UpdaterConfig.RuckZuck.$name = [int]$value
                    }
                }
            }
            if ($data.PSObject.Properties.Name -contains 'Drivers') {
                $drivers = $data.Drivers
                if ($drivers -isnot [pscustomobject]) { throw 'Drivers debe ser un objeto JSON.' }
                if ($drivers.PSObject.Properties.Name -contains 'Sources') {
                    if ($drivers.Sources -isnot [array]) { throw 'Drivers.Sources debe ser un arreglo.' }
                    foreach ($source in $drivers.Sources) { if ($source -cnotin @('Oem','Intel','WindowsUpdate')) { throw "Drivers.Sources solo admite Oem, Intel y WindowsUpdate: $source" } }
                    $script:UpdaterConfig.Drivers.Sources = @($drivers.Sources | Select-Object -Unique)
                }
                foreach ($name in @('IncludeFirmware','InstallVendorTool')) {
                    if ($drivers.PSObject.Properties.Name -contains $name) {
                        if ($drivers.$name -isnot [bool]) { throw "Drivers.$name debe ser true o false." }
                        $script:UpdaterConfig.Drivers.$name = $drivers.$name
                    }
                }
                if ($drivers.PSObject.Properties.Name -contains 'SkipIntelIds') {
                    if ($drivers.SkipIntelIds -isnot [array]) { throw 'Drivers.SkipIntelIds debe ser un arreglo.' }
                    foreach ($id in $drivers.SkipIntelIds) { if ("$id" -notmatch '^\d+$') { throw "ID de Intel omitido invalido: $id" } }
                    $script:UpdaterConfig.Drivers.SkipIntelIds = @($drivers.SkipIntelIds | ForEach-Object { "$_" } | Select-Object -Unique)
                }
                if ($drivers.PSObject.Properties.Name -contains 'InstallTimeoutSeconds') {
                    $value = $drivers.InstallTimeoutSeconds
                    if (($value -isnot [int] -and $value -isnot [long]) -or $value -lt 60 -or $value -gt 14400) { throw 'Drivers.InstallTimeoutSeconds debe ser un entero entre 60 y 14400.' }
                    $script:UpdaterConfig.Drivers.InstallTimeoutSeconds = [int]$value
                }
            }
            $schedule = $script:UpdaterConfig.Schedule
            if ($schedule.Enabled -isnot [bool]) { throw 'Schedule.Enabled debe ser true o false.' }
            if ($schedule.DayOfWeek -isnot [string] -or $schedule.DayOfWeek -cnotmatch '^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)$') { throw 'Schedule.DayOfWeek debe ser Monday a Sunday.' }
            if ($schedule.Time -isnot [string] -or $schedule.Time -notmatch '^([01][0-9]|2[0-3]):[0-5][0-9]$') { throw 'Schedule.Time debe usar HH:mm.' }
        } catch { throw "Configuracion invalida en $($script:UpdaterConfigPath): $($_.Exception.Message)" }
    } elseif (-not $DryRun) {
        Save-UpdaterConfiguration
    }
    Write-Info "Configuracion: $($script:UpdaterConfigPath)"
}

# Leer antes de actualizar o crear tareas; un JSON invalido detiene la ejecucion.
Initialize-UpdaterConfiguration
if ($script:UpdaterConfig.SkipStore) { $SkipStore = $true }
if ($script:UpdaterConfig.Verbose) { $script:DiagMode = $true }

# Asegurar carpeta de trabajo
if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
}
# Transcript
$LogFolder = Join-Path $OutputFolder 'Logs'
if (-not (Test-Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}
if ($LogRetentionDays -gt 0) {
    Get-ChildItem -LiteralPath $LogFolder -Filter 'Actualizar-*.log' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$LogRetentionDays) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
$tsFile = Join-Path $LogFolder ("Actualizar-{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
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

# Verifica la firma Authenticode de un archivo descargado.
# -Publisher: fragmento esperado del sujeto del certificado. -WarnOnly: solo avisa si falla.
function Test-DownloadSignature {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [string]$Publisher,
        [switch]$WarnOnly
    )
    $ok = $false; $detail = ''
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ($sig.Status -ne 'Valid') { $detail = "firma $($sig.Status)" }
        elseif ($Publisher -and $sig.SignerCertificate.Subject -notmatch [regex]::Escape($Publisher)) { $detail = "editor inesperado: $($sig.SignerCertificate.Subject)" }
        else { $ok = $true }
    } catch { $detail = $_.Exception.Message }
    if (-not $ok) {
        $msg = "Verificacion de firma de $(Split-Path $Path -Leaf): $detail"
        if ($WarnOnly) { Write-WarnMsg "⚠️ $msg" } else { Write-ErrMsg "❌ $msg" }
    }
    return ($ok -or $WarnOnly)
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
    # Cache: si hubo Internet hace menos de 2 minutos, no repetir las sondas.
    if ($script:InternetCheckedAt -and ((Get-Date) - $script:InternetCheckedAt).TotalSeconds -lt 120) { return $true }
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
                if ($resp.Content -match [regex]::Escape($p.Expect)) { $script:InternetCheckedAt = Get-Date; return $true }
            } else {
                if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 400) { $script:InternetCheckedAt = Get-Date; return $true }
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
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { $client.EndConnect($iar); $client.Close(); $script:InternetCheckedAt = Get-Date; return $true }
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
        if ($SkipStore) { $argsToPass += '-SkipStore' }
        if ($ForceWinGetReinstall) { $argsToPass += '-ForceWinGetReinstall' }
        if ($ScheduledRun) { $argsToPass += '-ScheduledRun' }
        if ($SkipScheduleTask) { $argsToPass += '-SkipScheduleTask' }
        if ($ReconfigureTask) { $argsToPass += '-ReconfigureTask' }
        if ($IncludePinned) { $argsToPass += '-IncludePinned' }
        if ($IncludeUnknown) { $argsToPass += '-IncludeUnknown' }
        if ($AllowReinstall) { $argsToPass += '-AllowReinstall' }
        if ($DryRun) { $argsToPass += '-DryRun' }
        if ($script:VerboseRequested) { $argsToPass += '-Verbose' }
        if ($ExcludeIds.Count -gt 0) { $argsToPass += @('-ExcludeIds',"`"$($ExcludeIds -join ',')`"") }
        $argsToPass += @('-RebootPolicy',$RebootPolicy,'-LogRetentionDays',"$LogRetentionDays")
        $argsToPass += @('-OutputFolder',"`"$OutputFolder`"")

        # Cerrar el transcript de este proceso: el pwsh relanzado crea el suyo.
        try { Stop-Transcript | Out-Null } catch {}
        if ($PSCommandPath) {
            $p = Start-Process -FilePath $pwshCmd -ArgumentList (@('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"") + $argsToPass) -Wait -PassThru
            exit $p.ExitCode
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
        if (-not (Test-DownloadSignature -Path $msiPath -Publisher 'Microsoft')) {
            Remove-Item -LiteralPath $msiPath -Force -ErrorAction SilentlyContinue
            throw 'El MSI descargado no tiene una firma valida de Microsoft.'
        }
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

function Repair-RZGetFiles {
    # Recupera un reemplazo interrumpido (corte, proceso detenido) y elimina temporales huerfanos de ejecuciones previas.
    param([string[]]$Targets)
    foreach ($target in $Targets) {
        $folder = Split-Path -Parent $target
        $leaf = [regex]::Escape((Split-Path -Leaf $target))
        $leftovers = @(Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^$leaf\.[0-9a-f]{32}\.(bak|download)$" })
        $backup = $leftovers | Where-Object { $_.Extension -eq '.bak' } | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($backup -and -not (Test-Path -LiteralPath $target)) {
            Move-Item -LiteralPath $backup.FullName -Destination $target -ErrorAction Stop
            Write-WarnMsg "⚠️ Se restauro $(Split-Path -Leaf $target) desde un reemplazo interrumpido."
        }
        $leftovers | Where-Object { Test-Path -LiteralPath $_.FullName } | ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
    }
}

function Install-RZGetFiles {
    # Reemplaza los archivos ya verificados como un par: si uno falla, se devuelven los anteriores a su lugar.
    param([object[]]$Files)
    $done = [Collections.Generic.List[object]]::new()
    try {
        foreach ($file in $Files) {
            $backup = $null
            if (Test-Path -LiteralPath $file.Target) {
                $backup = "$($file.Target).$([guid]::NewGuid().ToString('N')).bak"
                Move-Item -LiteralPath $file.Target -Destination $backup -ErrorAction Stop
            }
            $entry = [pscustomobject]@{ Target=$file.Target; Backup=$backup; Placed=$false }
            $done.Add($entry)
            Move-Item -LiteralPath $file.Tmp -Destination $file.Target -ErrorAction Stop
            $entry.Placed = $true
        }
    } catch {
        $rollbackFailed = $false
        for ($i = $done.Count - 1; $i -ge 0; $i--) {
            $entry = $done[$i]
            try {
                if ($entry.Placed) { Remove-Item -LiteralPath $entry.Target -Force -ErrorAction Stop }
                if ($entry.Backup) { Move-Item -LiteralPath $entry.Backup -Destination $entry.Target -ErrorAction Stop }
            } catch { $rollbackFailed = $true }
        }
        if ($rollbackFailed) { throw "Reemplazo de RZGet incompleto y sin reversion total; la proxima ejecucion intentara recuperarlo: $($_.Exception.Message)" }
        throw
    }
    foreach ($entry in $done) {
        if ($entry.Backup) { Remove-Item -LiteralPath $entry.Backup -Force -ErrorAction SilentlyContinue }
    }
}

function Download-RZGet {
    param([string]$DestinationFolder = $OutputFolder)
    $dest = Join-Path $DestinationFolder 'RZGet.exe'
    # RZGet.exe.config acompaña al ejecutable: proxy con credenciales por defecto, bindingRedirects y log en %TEMP%.
    $destConfig = "$dest.config"
    if ($DryRun) {
        if (Test-Path -LiteralPath $dest) { return $dest }
        throw 'DryRun no descarga RZGet; copie el ejecutable antes de consultar.'
    }
    try { Repair-RZGetFiles -Targets @($dest, $destConfig) } catch { Write-WarnMsg "⚠️ No se pudo recuperar un reemplazo previo de RZGet: $($_.Exception.Message)" }
    if ((Test-Path -LiteralPath $dest) -and (Test-Path -LiteralPath $destConfig) -and ((Get-Item -LiteralPath $dest).LastWriteTime -gt (Get-Date).AddDays(-$script:UpdaterConfig.RuckZuck.VersionCheckDays))) { return $dest }
    Set-Tls12Enable; Set-ProxyDefaults
    $staged = [Collections.Generic.List[object]]::new()
    try {
        $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/rzander/ruckzuck/releases/latest' -Headers @{ 'User-Agent'='UpdateAppsDrivers8.1' } -ErrorAction Stop
        # Se descargan y verifican ambos archivos antes de reemplazar alguno, para no mezclar versiones.
        foreach ($target in @($dest, $destConfig)) {
            $name = Split-Path -Leaf $target
            $asset = $release.assets | Where-Object { $_.name -eq $name } | Select-Object -First 1
            if (-not $asset -or $asset.digest -notmatch '^sha256:([a-fA-F0-9]{64})$') { throw "La version publicada no incluye un SHA-256 verificable para $name." }
            $expectedHash = $Matches[1]
            if ((Test-Path -LiteralPath $target) -and (Get-FileHash -LiteralPath $target -Algorithm SHA256 -ErrorAction Stop).Hash -eq $expectedHash) { continue }
            $tmp = "$target.$([guid]::NewGuid().ToString('N')).download"
            $staged.Add([pscustomobject]@{ Name=$name; Tmp=$tmp; Target=$target })
            Write-Info "📥 Descargando $name $($release.tag_name) y comprobando SHA-256..."
            $iwrParams = @{ Uri = $asset.browser_download_url; OutFile = $tmp; ErrorAction='Stop' }
            if ($PSVersionTable.PSVersion.Major -lt 7) { $iwrParams.UseBasicParsing = $true }
            Invoke-WebRequest @iwrParams
            if ((Get-FileHash -LiteralPath $tmp -Algorithm SHA256 -ErrorAction Stop).Hash -ne $expectedHash) { throw "SHA-256 de $name no coincide con el publicado por GitHub." }
        }
        if ($staged.Count -eq 0) { Write-Info "RZGet $($release.tag_name) ya esta actualizado." }
        foreach ($file in $staged) {
            if ($file.Target -eq $dest) { Test-DownloadSignature -Path $file.Tmp -WarnOnly | Out-Null }
        }
        Install-RZGetFiles -Files $staged.ToArray()
        foreach ($file in $staged) { Write-Ok "✅ $($file.Name) descargado en: $($file.Target)" }
        (Get-Item -LiteralPath $dest).LastWriteTime = Get-Date
    } catch {
        foreach ($file in $staged) { Remove-Item -LiteralPath $file.Tmp -Force -ErrorAction SilentlyContinue }
        if (-not (Test-Path -LiteralPath $dest)) { throw }
        Write-WarnMsg "⚠️ No se pudo verificar o refrescar RZGet; se usa la copia existente: $($_.Exception.Message)"
    }
    return $dest
}

function Invoke-RuckZuckProcess {
    param([string]$Executable, [string[]]$Arguments, [int]$TimeoutSeconds, [string]$LogLabel)
    $logDir = Join-Path $LogFolder 'RuckZuck'
    New-Item -ItemType Directory -Path $logDir -Force -ErrorAction Stop | Out-Null
    $safeLabel = $LogLabel -replace '[^\w.\-]', '_'
    $logBase = Join-Path $logDir (('{0:yyyyMMdd-HHmmss}-{1}-{2}' -f (Get-Date), $safeLabel, [guid]::NewGuid().ToString('N')))
    $outPath = "$logBase.stdout.log"; $errPath = "$logBase.stderr.log"
    $quotedArgs = @($Arguments | ForEach-Object { '"' + $_.Replace('"','\"') + '"' })
    Write-Diag "Ejecutando: `"$Executable`" $($quotedArgs -join ' ')"
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $Executable -ArgumentList $quotedArgs -PassThru -WindowStyle Hidden -RedirectStandardOutput $outPath -RedirectStandardError $errPath -ErrorAction Stop
    $finished = $process.WaitForExit($TimeoutSeconds * 1000)
    if (-not $finished) {
        try { Stop-Process -Id $process.Id -Force -ErrorAction Stop; $process.WaitForExit() } catch { Write-WarnMsg "No se pudo detener RZGet ($($process.Id)): $($_.Exception.Message)" }
    }
    Write-Diag ("RZGet {0} en {1:N1} s; salida: {2}" -f $(if ($finished) { "termino con codigo $($process.ExitCode)" } else { "supero $TimeoutSeconds s y se detuvo" }), $watch.Elapsed.TotalSeconds, $outPath)
    $stdout = if (Test-Path -LiteralPath $outPath) { @(Get-Content -LiteralPath $outPath -ErrorAction SilentlyContinue) } else { @() }
    $stderr = if (Test-Path -LiteralPath $errPath) { @(Get-Content -LiteralPath $errPath -ErrorAction SilentlyContinue) } else { @() }
    return [pscustomobject]@{ TimedOut=(-not $finished); ExitCode=$(if ($finished) { $process.ExitCode } else { $null }); Stdout=$stdout; Stderr=$stderr; OutPath=$outPath; ErrPath=$errPath }
}

function Get-RuckZuckPending {
    param([string]$Executable, [string[]]$ScopeArgs, [int]$DelayDays=0, [string]$LogLabel='consulta')
    $argsList = @('update','--list','--all') + @($ScopeArgs)
    if ($DelayDays -gt 0) { $argsList += "--delay=$DelayDays" }
    $result = Invoke-RuckZuckProcess -Executable $Executable -Arguments $argsList -TimeoutSeconds $script:UpdaterConfig.RuckZuck.ScanTimeoutSeconds -LogLabel $LogLabel
    if ($result.TimedOut) { throw "Consulta RZGet supero el tiempo limite. Log: $($result.ErrPath)" }
    if ($result.ExitCode -ne 0) { throw "Consulta RZGet fallo con codigo $($result.ExitCode). Logs: $($result.OutPath), $($result.ErrPath)" }
    if (@($result.Stderr | Where-Object { $_ -match '\S' }).Count -gt 0 -or @($result.Stdout | Where-Object { $_ -match '^\s*(\[.*\s(ERR|FTL)\]|E\d+:|E2)' }).Count -gt 0) {
        throw "Consulta RZGet produjo errores. Logs: $($result.OutPath), $($result.ErrPath)"
    }
    $lines = @($result.Stdout | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $invalid = @($lines | Where-Object { $_ -notmatch '^[\w.+\-]+$' })
    if ($invalid.Count -gt 0) { throw "La consulta RZGet devolvio lineas inesperadas. Log: $($result.OutPath)" }
    return @($lines | Select-Object -Unique)
}

function Update-RuckZuckApps {
    Write-Section 1 5 'Aplicaciones (RuckZuck)'
    if (-not (Test-Internet -VerboseMode)) {
        Write-ErrMsg "❌ Sin Internet. Omitiendo RZGet."
        return
    }
    try { $rzPath = Download-RZGet } catch { $rzPath = $null; Write-WarnMsg "Descarga RZGet: $($_.Exception.Message)" }
    if (-not $rzPath) {
        Write-ErrMsg "❌ No se pudo obtener RZGet.exe."
        $script:Failures.Add('RZGet: no disponible')
        return
    }
    # RZGet separa las apps por ámbito: instaladas para la máquina y para el usuario (--user).
    # Bajo SYSTEM (tarea programada) '--user' apuntaria al perfil de SYSTEM, sin apps: solo se revisa la máquina.
    $scopes = @(@{ Name = 'máquina'; Args = @() })
    if (-not $ScheduledRun) { $scopes += @{ Name = 'usuario'; Args = @('--user') } }

    $haltRuckZuck = $false
    foreach ($scope in $scopes) {
        Write-Host ("  ▸ Ámbito: {0}" -f $scope.Name) -ForegroundColor Cyan
        try {
            $scopeArgs = @($scope.Args)
            # 'update --list' devuelve un nombre corto (Shortname) por linea; vacio si no hay nada.
            $pending = @(Get-RuckZuckPending -Executable $rzPath -ScopeArgs $scopeArgs -DelayDays $script:UpdaterConfig.RuckZuck.DelayDays -LogLabel "lista-$($scope.Name)")
            foreach ($excludedShort in @($pending | Where-Object { $_ -in $script:UpdaterConfig.RuckZuck.SkipShortNames })) {
                Write-Detail "Omitido por configuracion: $excludedShort"
                $script:Skipped.Add("RuckZuck ${excludedShort}: excluido")
            }
            $pending = @($pending | Where-Object { $_ -notin $script:UpdaterConfig.RuckZuck.SkipShortNames })
            if ($pending.Count -eq 0) {
                Write-Info "    No se detectaron actualizaciones (RZGet devolvio una lista vacia)."
                continue
            }
            Write-WarnMsg ("    📋 Actualizaciones disponibles: {0}" -f $pending.Count)
            if ($DryRun) {
                $pending | ForEach-Object { Write-Host "      • $_" -ForegroundColor White }
                continue
            }
            $index = 0
            $needsVerification = [Collections.Generic.List[object]]::new()
            foreach ($short in $pending) {
                $index++
                # En modo detallado se termina la linea para que las lineas [diag] no se mezclen con el resultado.
                Write-Host ("    [{0}/{1}] {2} ... " -f $index, $pending.Count, $short) -NoNewline:(-not $script:DiagMode) -ForegroundColor White
                try {
                    $result = Invoke-RuckZuckProcess -Executable $rzPath -Arguments (@('update',$short,'--retry') + $scopeArgs) -TimeoutSeconds $script:UpdaterConfig.RuckZuck.InstallTimeoutSeconds -LogLabel "update-$short"
                    $code = $result.ExitCode
                    if ($result.TimedOut) {
                        Write-Host 'TIEMPO AGOTADO' -ForegroundColor Red
                        Write-WarnMsg 'Se detuvo RZGet. Windows Installer podria continuar en segundo plano; se omiten los siguientes paquetes de este ambito.'
                        $script:Failures.Add("RuckZuck ${short}: tiempo agotado; log $($result.OutPath)")
                        $haltRuckZuck = $true
                        break
                    } elseif ($code -eq 0 -and (($result.Stdout -join "`n") -match ('(?im)^(?:\[[^\r\n]*\]\s*)?Installation finished:\s*[\x22\x27]?' + [regex]::Escape($short) + '(?:[\x22\x27\s]|$)'))) {
                        Write-Host 'PENDIENTE DE VERIFICACION' -ForegroundColor Yellow
                        $needsVerification.Add([pscustomobject]@{ ShortName=$short; Log=$result.OutPath })
                    } else {
                        Write-Host "FALLO O NO CONFIRMADO (código $code)" -ForegroundColor Red
                        @($result.Stdout + $result.Stderr) | Where-Object { $_ -match '\S' } | Select-Object -Last 3 | ForEach-Object { Write-Detail $_.Trim() }
                        Write-Detail "Logs completos: $($result.OutPath), $($result.ErrPath)"
                        # La causa que informa RZGet (ERR/FTL o "Installation failed") es mas util en el resumen que el codigo 0.
                        $reason = @($result.Stdout + $result.Stderr) | Where-Object { $_ -match '\[[^\]]*\s(ERR|FTL)\]|Installation failed' } | Select-Object -Last 1
                        $reason = if ($reason) { ($reason -replace '^\s*\[[^\]]*\]\s*', '').Trim().TrimEnd('.') } else { "codigo $code o instalacion no confirmada" }
                        $script:Failures.Add("RuckZuck ${short}: $reason; log $($result.OutPath)")
                    }
                } catch {
                    Write-Host 'ERROR' -ForegroundColor Red
                    Write-Detail $_.Exception.Message
                    $script:Failures.Add("RuckZuck ${short}: $($_.Exception.Message)")
                }
            }
            if ($needsVerification.Count -gt 0) {
                try {
                    $remaining = @(Get-RuckZuckPending -Executable $rzPath -ScopeArgs $scopeArgs -LogLabel "verificacion-$($scope.Name)")
                    foreach ($attempt in $needsVerification) {
                        if ($attempt.ShortName -in $remaining) {
                            Write-WarnMsg "⚠️ $($attempt.ShortName) sigue pendiente; revise $($attempt.Log)."
                            $script:Failures.Add("RuckZuck $($attempt.ShortName): sigue pendiente; log $($attempt.Log)")
                        } else {
                            Write-Ok "✅ $($attempt.ShortName): RZGet reporto finalizacion y ya no figura pendiente."
                            $script:Successes.Add("RuckZuck $($attempt.ShortName)")
                        }
                    }
                } catch {
                    Write-WarnMsg "No se pudo verificar el resultado RuckZuck: $($_.Exception.Message)"
                    foreach ($attempt in $needsVerification) { $script:Failures.Add("RuckZuck $($attempt.ShortName): resultado sin verificar; log $($attempt.Log)") }
                }
            }
            if ($haltRuckZuck) { Write-WarnMsg 'Se omiten los demas ambitos de RuckZuck hasta revisar el instalador pendiente.'; break }
        } catch {
            $script:Failures.Add("RZGet ($($scope.Name)): $($_.Exception.Message)")
            Write-ErrMsg "    ❌ Error RZGet ($($scope.Name)): $($_.Exception.Message)"
        }
    }
}

# -------------------------
# WinGet
# -------------------------
$script:WinGetExecutable = $null

function Invoke-Download {
    param([Parameter(Mandatory=$true)][string]$Uri, [Parameter(Mandatory=$true)][string]$OutFile)
    Set-Tls12Enable; Set-ProxyDefaults
    $params = @{ Uri=$Uri; OutFile=$OutFile; ErrorAction='Stop' }
    if ($PSVersionTable.PSVersion.Major -lt 7) { $params.UseBasicParsing = $true }
    Write-Diag "Descargando $Uri -> $OutFile"
    Invoke-WebRequest @params | Out-Null
    Write-Diag ("Descargados {0:N0} bytes" -f (Get-Item -LiteralPath $OutFile -ErrorAction SilentlyContinue).Length)
}

function Get-WindowsPowerShellPath {
    $path = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $path) { return $path }
    return $null
}

function Test-AppxDeploymentAvailable {
    $windowsPowerShell = Get-WindowsPowerShellPath
    if (-not $windowsPowerShell) { return $false }
    & $windowsPowerShell -NoProfile -NonInteractive -Command "if ((Get-Command Add-AppxPackage -ErrorAction SilentlyContinue) -and (Get-Command Add-AppxProvisionedPackage -ErrorAction SilentlyContinue)) { exit 0 }; exit 1" 2>$null
    return ($LASTEXITCODE -eq 0)
}

function Invoke-WindowsPowerShellCommand {
    param([Parameter(Mandatory=$true)][string]$Command)
    $windowsPowerShell = Get-WindowsPowerShellPath
    if (-not $windowsPowerShell) { throw 'Windows PowerShell 5.1 no esta disponible.' }
    Write-Diag "Windows PowerShell 5.1: $Command"
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
    $output = @(& $windowsPowerShell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encodedCommand 2>&1)
    if ($LASTEXITCODE -ne 0) {
        $details = ($output | Out-String).Trim()
        throw "Windows PowerShell devolvio el codigo $LASTEXITCODE. $details"
    }
}

function Get-WinGetExecutable {
    if ($script:WinGetExecutable -and (Test-Path -LiteralPath $script:WinGetExecutable)) { return $script:WinGetExecutable }
    $command = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $command) { $command = Get-Command winget -ErrorAction SilentlyContinue }
    if ($command -and $command.Source -and (Test-Path -LiteralPath $command.Source)) {
        $script:WinGetExecutable = $command.Source
        return $script:WinGetExecutable
    }

    # Server/SYSTEM no siempre tienen el alias de WindowsApps; usar la ubicacion real del paquete.
    $packageLocation = $null
    if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
        $package = Get-AppxPackage -Name Microsoft.DesktopAppInstaller -AllUsers -ErrorAction SilentlyContinue |
            Sort-Object Version -Descending | Select-Object -First 1
        if ($package) { $packageLocation = $package.InstallLocation }
    } elseif (Test-AppxDeploymentAvailable) {
        # Los cmdlets AppX suelen estar disponibles solo en Windows PowerShell 5.1, no en pwsh.
        $windowsPowerShell = Get-WindowsPowerShellPath
        $packageLocation = & $windowsPowerShell -NoProfile -NonInteractive -Command "(Get-AppxPackage -Name Microsoft.DesktopAppInstaller -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1).InstallLocation" 2>$null | Select-Object -First 1
    }
    if ($packageLocation) {
        $candidate = Join-Path $packageLocation 'winget.exe'
        if (Test-Path -LiteralPath $candidate) {
            $script:WinGetExecutable = $candidate
            return $script:WinGetExecutable
        }
    }
    return $null
}

function Invoke-WinGet {
    param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments)
    $executable = Get-WinGetExecutable
    if (-not $executable) { throw 'WinGet no esta instalado o no se encontro winget.exe.' }
    Write-Diag "Ejecutando: `"$executable`" $($Arguments -join ' ')"
    $watch = [Diagnostics.Stopwatch]::StartNew()
    & $executable @Arguments
    Write-Diag ("winget termino con codigo {0} en {1:N1} s" -f $LASTEXITCODE, $watch.Elapsed.TotalSeconds)
}

function Test-WinGetInstalled {
    $executable = Get-WinGetExecutable
    if (-not $executable) { return $false }
    try {
        $version = & $executable --version 2>$null
        return ($LASTEXITCODE -eq 0 -and $version)
    } catch { return $false }
}

function Confirm-WinGetInstallation {
    if ($ScheduledRun -or -not $script:UpdaterConfig.AskQuestions) { return $script:UpdaterConfig.InstallWinGetIfMissing }
    if (-not [Environment]::UserInteractive) {
        Write-WarnMsg 'WinGet no esta instalado y esta ejecucion no tiene interfaz para solicitar confirmacion.'
        return $false
    }

    do {
        $answer = Read-Host 'WinGet no esta instalado. Desea instalarlo ahora? [S/N]'
    } while ($answer -notmatch '^(?i:s|si|y|yes|n|no)$')

    return ($answer -match '^(?i:s|si|y|yes)$')
}

function Install-VCRedist {
    $architecture = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    if ($env:PROCESSOR_ARCHITECTURE -match 'ARM64') { $architecture = 'arm64' }
    $tempFolder = Join-Path $env:TEMP ("VCRedist-" + [guid]::NewGuid().ToString())
    try {
        New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null
        $installer = Join-Path $tempFolder "vc_redist.$architecture.exe"
        Write-Info "Descargando Visual C++ Redistributable ($architecture)..."
        Invoke-Download "https://aka.ms/vs/17/release/vc_redist.$architecture.exe" $installer
        if (-not (Test-DownloadSignature -Path $installer -Publisher 'Microsoft')) { throw 'vc_redist sin firma valida de Microsoft.' }
        $process = Start-Process -FilePath $installer -ArgumentList '/install','/quiet','/norestart' -Wait -PassThru
        if ($process.ExitCode -notin @(0, 3010)) { throw "El instalador VC++ devolvio el codigo $($process.ExitCode)." }
        Write-Ok 'Visual C++ Redistributable instalado.'
        return $true
    } catch {
        Write-WarnMsg "No se pudo instalar Visual C++ Redistributable: $($_.Exception.Message)"
        return $false
    } finally {
        Remove-Item -LiteralPath $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Test-AppSideloadingPolicy {
    try {
        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx'
        $policy = Get-ItemProperty -LiteralPath $policyPath -ErrorAction Stop
        if ($policy.AllowAllTrustedApps -eq 0 -and $null -ne $policy.AllowAllTrustedApps) {
            Write-WarnMsg 'AllowAllTrustedApps=0: la politica del servidor restringe los paquetes AppX. Se intentara instalar respetando esa politica.'
        } else {
            Write-Info 'Politica AppX consultada; no se modificara la configuracion del servidor.'
        }
    } catch {
        Write-Info 'Sin politica AppX consultable. Se intentara instalar con la configuracion actual del servidor.'
    }
}

function Install-WinGetWithClientModule {
    try {
        Write-Info 'Intentando reparar WinGet con Microsoft.WinGet.Client...'
        Set-Tls12Enable
        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -Force -Scope AllUsers -ErrorAction Stop | Out-Null
        }
        Install-Module -Name Microsoft.WinGet.Client -Repository PSGallery -Scope AllUsers -Force -AllowClobber -ErrorAction Stop | Out-Null
        Import-Module Microsoft.WinGet.Client -Force -ErrorAction Stop
        Repair-WinGetPackageManager -AllUsers -Latest -Force -ErrorAction Stop | Out-Null
        Start-Sleep -Seconds 3
        if (Test-WinGetInstalled) { Write-Ok 'WinGet instalado mediante Microsoft.WinGet.Client.'; return $true }
        throw 'La reparacion termino sin que se pudiera verificar winget.exe.'
    } catch {
        Write-WarnMsg "El fallback Microsoft.WinGet.Client fallo: $($_.Exception.Message)"
        return $false
    }
}

function Install-WinGet {
    if (-not (Test-IsAdmin)) { Write-ErrMsg 'Se requiere Admin para instalar WinGet.'; return $false }
    if (-not (Test-Internet -VerboseMode)) { Write-ErrMsg 'Sin Internet para instalar WinGet.'; return $false }
    if (-not (Test-AppxDeploymentAvailable)) {
        $installationType = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).InstallationType
        if ($installationType -match 'Core') {
            Write-ErrMsg 'Windows Server Core no es compatible con WinGet: requiere MSIX/AppX y Desktop Experience.'
        } else {
            Write-ErrMsg 'Faltan los cmdlets AppX. Se requiere Windows 10/11 o Windows Server 2019 LTSC o posterior con Desktop Experience.'
        }
        return $false
    }

    Test-AppSideloadingPolicy
    $architecture = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    if ($env:PROCESSOR_ARCHITECTURE -match 'ARM64') { $architecture = 'arm64' }
    $tempFolder = Join-Path $env:TEMP ("WinGetInstall-" + [guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null
    try {
        Install-VCRedist | Out-Null
        Write-Info 'Descargando WinGet y dependencias para LTSC/Server...'
        $bundlePath = Join-Path $tempFolder 'WinGet.msixbundle'
        $licensePath = Join-Path $tempFolder 'License.xml'

        $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/microsoft/winget-cli/releases/latest' -Headers @{ 'User-Agent'='WinGet-Installer' } -ErrorAction Stop
        $bundleUrl = ($release.assets | Where-Object { $_.name -like '*.msixbundle' } | Select-Object -First 1).browser_download_url
        $licenseUrl = ($release.assets | Where-Object { $_.name -like '*License1.xml' } | Select-Object -First 1).browser_download_url
        if (-not $bundleUrl -or -not $licenseUrl) { throw 'No se encontraron los archivos de WinGet en la release actual.' }
        Invoke-Download $bundleUrl $bundlePath
        Invoke-Download $licenseUrl $licensePath
        if (-not (Test-DownloadSignature -Path $bundlePath -Publisher 'Microsoft')) { throw 'El bundle de WinGet no tiene firma valida de Microsoft.' }

        # Usar las dependencias de la misma release: WinGet 1.29 requiere WindowsAppRuntime 1.8.
        $dependencyAsset = $release.assets | Where-Object { $_.name -eq 'DesktopAppInstaller_Dependencies.zip' } | Select-Object -First 1
        if (-not $dependencyAsset) { throw 'La release no publica DesktopAppInstaller_Dependencies.zip.' }
        $dependencyZip = Join-Path $tempFolder 'Dependencies.zip'
        $dependencyFolder = Join-Path $tempFolder 'Dependencies'
        Write-Info "Descargando dependencias oficiales de WinGet $($release.tag_name) ($architecture)..."
        Invoke-Download $dependencyAsset.browser_download_url $dependencyZip
        Expand-Archive -LiteralPath $dependencyZip -DestinationPath $dependencyFolder -ErrorAction Stop
        $architectureFolder = Join-Path $dependencyFolder $architecture
        $dependencies = @(Get-ChildItem -LiteralPath $architectureFolder -File -Recurse -ErrorAction Stop |
            Where-Object { $_.Extension -in @('.appx', '.msix') } | Sort-Object Name)
        if ($dependencies.Count -eq 0) { throw "No se encontraron dependencias para $architecture." }
        foreach ($dependencyFile in $dependencies) {
            $dependency = $dependencyFile.FullName
            Write-Info "Instalando dependencia: $($dependencyFile.Name)..."
            $escapedPath = $dependency.Replace("'", "''")
            try { Invoke-WindowsPowerShellCommand "Add-AppxPackage -Path '$escapedPath' -ErrorAction Stop" } catch { Write-WarnMsg "No se pudo instalar $($dependencyFile.Name): $($_.Exception.Message)" }
            try { Invoke-WindowsPowerShellCommand "Add-AppxProvisionedPackage -Online -PackagePath '$escapedPath' -SkipLicense -ErrorAction Stop | Out-Null" } catch { Write-WarnMsg "No se pudo aprovisionar: $(Split-Path $dependency -Leaf)" }
        }
        $escapedBundle = $bundlePath.Replace("'", "''")
        $escapedLicense = $licensePath.Replace("'", "''")
        Invoke-WindowsPowerShellCommand "Add-AppxPackage -Path '$escapedBundle' -ErrorAction Stop"
        Invoke-WindowsPowerShellCommand "Add-AppxProvisionedPackage -Online -PackagePath '$escapedBundle' -LicensePath '$escapedLicense' -ErrorAction Stop | Out-Null"
        Start-Sleep -Seconds 3
        if (Test-WinGetInstalled) { Write-Ok 'WinGet instalado y verificado.'; return $true }
        throw 'WinGet no pudo verificarse despues de la instalacion.'
    } catch {
        Write-WarnMsg "La instalacion AppX directa fallo: $($_.Exception.Message)"
        if (Install-WinGetWithClientModule) { return $true }
        Write-ErrMsg 'No se pudo instalar WinGet mediante AppX ni Microsoft.WinGet.Client.'
        return $false
    } finally {
        Remove-Item -LiteralPath $tempFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Ensure-WinGetSources {
    try {
        Write-Detail "Preparando fuentes de WinGet..."
        Invoke-WinGet source update --disable-interactivity | Out-Null
        Invoke-WinGet source reset --force --disable-interactivity | Out-Null  # restablece winget + msstore (requiere --force)
    } catch {
        Write-WarnMsg "⚠️ No se pudieron preparar las fuentes de WinGet: $($_.Exception.Message)"
    }
}

# Opciones opcionales de 'winget upgrade': por defecto se respetan pines y versiones desconocidas.
function Get-WinGetUpgradeFlags {
    $flags = @()
    if ($IncludeUnknown) { $flags += '--include-unknown' }
    if ($IncludePinned)  { $flags += '--include-pinned' }
    return $flags
}

# Ids a omitir: -ExcludeIds + exclusiones.txt (junto al script).
function Get-ExcludedIds {
    $list = [Collections.Generic.List[string]]::new()
    foreach ($e in $script:UpdaterConfig.SkipPackages) { $list.Add($e) }
    foreach ($e in $ExcludeIds) { $list.Add($e) }
    $file = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'exclusiones.txt' } else { $null }
    if ($file -and (Test-Path -LiteralPath $file)) {
        Get-Content -LiteralPath $file -ErrorAction SilentlyContinue |
            ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^#' } | ForEach-Object { $list.Add($_) }
    }
    return @($list | Select-Object -Unique)
}

function Get-WinGetUpgradesList {
    $wgArgs = @('upgrade','--accept-source-agreements') + @(Get-WinGetUpgradeFlags) + @('--disable-interactivity')
    $text = Invoke-WinGet @wgArgs | Out-String
    $lines = $text -split "`n" | Where-Object { $_ -match '^\S' }
    return $lines
}

# Convierte la salida de 'winget upgrade' en objetos Name/Id/Version/Available.
function Get-WinGetUpgradeItems {
    param([string[]]$Lines)
    # Se parsea por POSICIÓN de columna (según la cabecera): cuando el nombre llena su columna
    # solo queda 1 espacio antes del Id y separar por 2+ espacios devolvía la versión como Id.
    if (-not $PSBoundParameters.ContainsKey('Lines')) { $Lines = Get-WinGetUpgradesList }
    $idStart = -1; $verStart = -1; $availStart = -1
    $items = foreach ($raw in $Lines) {
        $line = $raw.TrimEnd()
        if ($line -match '^Name\s+Id\s+Version') {                      # cabecera (se repite en la 2ª tabla)
            $idStart    = $line.IndexOf('Id')
            $verStart   = $line.IndexOf('Version')
            $availStart = $line.IndexOf('Available')
            continue
        }
        if ($idStart -lt 0) { continue }
        if ($line -match '^-+$') { continue }                           # separador
        if ($line -match '\d+\s+upgrades?\s+available') { continue }    # resumen
        if ($line -match '^(No\s|The following)') { continue }
        if ($line.Length -le $idStart) { continue }
        $cut = {
            param($from, $to)
            if ($from -lt 0 -or $line.Length -le $from) { return '' }
            $len = if ($to -gt $from -and $line.Length -ge $to) { $to - $from } else { $line.Length - $from }
            $line.Substring($from, $len).Trim()
        }
        $verEnd = if ($availStart -gt $verStart) { $availStart } else { -1 }
        [pscustomobject]@{
            Name      = $line.Substring(0, [Math]::Min($idStart, $line.Length)).Trim()
            Id        = (& $cut $idStart $verStart)
            Version   = (& $cut $verStart $verEnd)
            Available = $(if ($availStart -gt 0) { & $cut $availStart -1 } else { '' })
        }
    }
    # Quitar la columna Source (último token) de Available y filtrar Ids no validos.
    $items = @($items | Where-Object { $_.Id -match '^[\w\.\+\-]+$' })
    foreach ($i in $items) { $i.Available = ($i.Available -split '\s+')[0] }
    return @($items | Sort-Object Id -Unique)
}

function Get-WinGetUpgradeIds {
    param([string[]]$Lines)
    if (-not $PSBoundParameters.ContainsKey('Lines')) { $Lines = Get-WinGetUpgradesList }
    return @(Get-WinGetUpgradeItems -Lines $Lines | ForEach-Object { $_.Id })
}

function Resolve-WinGetFailure {
    param(
        [Parameter(Mandatory=$true)][string]$Id,
        [string]$Details,
        [ValidateSet('upgrade','install')][string]$Operation = 'upgrade'
    )
    # El ID se obtiene de la tabla WinGet; escapar comillas para el comando copiable.
    $quotedId = $Id.Replace("'", "''")
    $manualCommand = "winget $Operation --id '$quotedId' --exact --interactive --accept-package-agreements --accept-source-agreements"
    $diagnosticFolder = Join-Path $env:LOCALAPPDATA 'Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\DiagOutputDir'
    try {
        $recoveryFile = Join-Path $LogFolder 'WinGet-Recuperacion-manual.log'
        @("[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Id", $Details, "Comando: $manualCommand", "Transcript: $tsFile", "Diagnosticos WinGet: $diagnosticFolder", '') |
            Add-Content -LiteralPath $recoveryFile -Encoding UTF8 -ErrorAction Stop
        Write-Info "Comando y error guardados en $recoveryFile"
    } catch { Write-WarnMsg "No se pudo guardar la recuperacion: $($_.Exception.Message)" }

    $script:Failures.Add("WinGet ${Id}: $Operation fallido")
    if ($ScheduledRun -or -not $script:UpdaterConfig.AskQuestions -or -not [Environment]::UserInteractive) {
        Write-WarnMsg "Recuperacion manual pendiente para ${Id}: $manualCommand"
        return
    }
    Write-Host "No se pudo completar ${Id}. Opciones:"
    Write-Host '  1. Reintentar con WinGet y el instalador visible'
    Write-Host '  2. Mostrar comando para ejecutarlo manualmente despues'
    Write-Host '  3. Omitir y continuar con los demas paquetes'
    do { $choice = (Read-Host 'Seleccione una opcion (1-3)').Trim() } while ($choice -notmatch '^[1-3]$')
    if ($choice -eq '2') { Write-Host $manualCommand -ForegroundColor Cyan; return }
    if ($choice -ne '1') {
        $script:UpdaterConfig.SkipPackages = @(@($script:UpdaterConfig.SkipPackages) + $Id | Select-Object -Unique)
        try { Save-UpdaterConfiguration; Write-Info "$Id guardado en SkipPackages para futuras ejecuciones." }
        catch { Write-WarnMsg "No se pudo guardar la omision: $($_.Exception.Message)" }
        return
    }
    try {
        Write-Info "Reintentando ${Id} con instalador interactivo..."
        Invoke-WinGet $Operation --id $Id --exact --interactive --accept-package-agreements --accept-source-agreements | ForEach-Object { Write-Host $_ }
        if ($LASTEXITCODE -eq 0) { Write-Ok "$Id completado mediante instalacion interactiva."; $script:Successes.Add("WinGet ${Id}") }
        else {
            Write-WarnMsg "El reintento de $Id fallo (codigo $LASTEXITCODE). Comando manual: $manualCommand"
            "Reintento de ${Id}: codigo $LASTEXITCODE" | Add-Content -LiteralPath $recoveryFile -Encoding UTF8 -ErrorAction SilentlyContinue
        }
    } catch { Write-WarnMsg "Error al reintentar ${Id}: $($_.Exception.Message). Comando manual: $manualCommand" }
}

function Update-WinGetApps {
    Write-Section 2 5 'Aplicaciones (WinGet)'
    if (-not (Test-WinGetInstalled) -or $ForceWinGetReinstall) {
        Write-WarnMsg "WinGet no esta disponible o se solicito reinstalacion."
        $installApproved = $ForceWinGetReinstall -or (Confirm-WinGetInstallation)
        if (-not $installApproved) {
            Write-WarnMsg 'Instalacion de WinGet omitida por el usuario.'
            return
        }
        if (-not (Install-WinGet)) {
            Write-ErrMsg "❌ WinGet no está instalado o disponible en este sistema. Omitiendo."
            return
        }
    }
    $internet = Test-Internet -VerboseMode
    if (-not $internet) {
        Write-WarnMsg "⚠️ Sondas HTTP fallaron; pruebo 'winget source list' para confirmar conectividad..."
        try { Invoke-WinGet source list --disable-interactivity | Out-Null; $internet = $true } catch { }
    }
    if (-not $internet) { Write-ErrMsg "❌ Sin Internet. Omitiendo WinGet."; return }

    Ensure-WinGetSources
    try {
        $upgrades = Get-WinGetUpgradesList
        $items = @(Get-WinGetUpgradeItems -Lines $upgrades)
        $excluded = Get-ExcludedIds

        if ($items.Count -eq 0) {
            if (($upgrades -join "`n") -match 'No installed package found|No applicable upgrade') {
                Write-Ok "✅ No hay actualizaciones WinGet disponibles."
                return
            }
            Write-WarnMsg "⚠️ No se pudo interpretar la lista de WinGet."
            if ($DryRun) { return }
            Write-WarnMsg "   Reintento con 'winget upgrade --all'..."
            if ($excluded.Count -gt 0) { Write-WarnMsg 'Se omite el lote para respetar las exclusiones configuradas.'; return }
            $wgArgs = @('upgrade','--all') + @(Get-WinGetUpgradeFlags) + @('--accept-package-agreements','--accept-source-agreements','--silent','--disable-interactivity')
            Invoke-WinGet @wgArgs
            if ($LASTEXITCODE -ne 0) { $script:Failures.Add("WinGet upgrade --all: codigo $LASTEXITCODE") }
            else { $script:Successes.Add('WinGet (--all)') }
            return
        }

        # Tabla de pendientes
        Write-WarnMsg ("📋 Actualizaciones disponibles: {0}" -f $items.Count)
        ($items | Format-Table @{n='Aplicación';e={$_.Name}}, @{n='Id';e={$_.Id}}, @{n='Actual';e={$_.Version}}, @{n='Nueva';e={$_.Available}} -AutoSize |
            Out-String -Width 200).TrimEnd().Split("`n") | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "  $($_.TrimEnd())" -ForegroundColor White }

        if ($DryRun) { Write-WarnMsg "DryRun: no se instala nada con WinGet."; return }

        $toInstall = @($items | Where-Object { $excluded -notcontains $_.Id })
        foreach ($skippedItem in @($items | Where-Object { $excluded -contains $_.Id })) {
            Write-Detail "Omitido por exclusión: $($skippedItem.Id)"
            $script:Skipped.Add("WinGet $($skippedItem.Id): excluido")
        }
        Write-Host ''

        # Se actualiza paquete por paquete: si uno falla (p. ej. requiere --location),
        # 'winget upgrade --all' aborta todo el lote restante. Uno por uno, un fallo no bloquea al resto.
        $index = 0
        foreach ($item in $toInstall) {
            $index++
            $id = $item.Id
            $label = "  [{0}/{1}] {2} ({3} → {4})" -f $index, $toInstall.Count, $id, $item.Version, $item.Available
            Write-Host $label -NoNewline -ForegroundColor White
            Write-Host ' ... ' -NoNewline:(-not $script:DiagMode)
            try {
                $packageOutput = [Collections.Generic.List[string]]::new()
                $wgArgs = @('upgrade','--id',$id,'--exact') + @(Get-WinGetUpgradeFlags) + @('--accept-package-agreements','--accept-source-agreements','--silent','--disable-interactivity')
                Invoke-WinGet @wgArgs 2>&1 | ForEach-Object { $packageOutput.Add([string]$_) }
                $code = $LASTEXITCODE
                if ($code -eq 0) {
                    Write-Ok 'OK'
                    $script:Successes.Add("WinGet $id")
                } elseif ($code -eq -1978334956) {
                    # WinGet no puede actualizar este paquete (lo gestiona el editor): no es un fallo ni se reintenta.
                    Write-Host 'OMITIDO' -ForegroundColor Cyan
                    Write-Detail "El editor no permite actualizarlo con WinGet; use su propio método."
                    $script:Skipped.Add("WinGet ${id}: actualizar con el método del editor")
                } elseif ($code -eq -1978335090 -and -not $AllowReinstall -and $id -ne 'Microsoft.Edge') {
                    Write-Host 'REQUIERE REINSTALAR' -ForegroundColor Yellow
                    Write-Detail "Tecnología de instalación distinta. Use -AllowReinstall para permitir desinstalar + reinstalar."
                    $script:Failures.Add("WinGet ${id}: requiere reinstalacion manual (-AllowReinstall)")
                } elseif ($code -eq -1978335090) {
                    Write-Host 'REINSTALANDO' -ForegroundColor Yellow
                    if ($id -eq 'Microsoft.Edge') {
                        # Edge no se desinstala: se fuerza su actualizador propio.
                        $eu = @("${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe","$env:ProgramFiles\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
                        if ($eu) {
                            Start-Process -FilePath $eu -ArgumentList '/ua /installsource scheduler' -Wait -NoNewWindow
                            Write-Detail "Edge: se lanzó su actualizador integrado."
                            $script:Successes.Add("WinGet $id (actualizador propio)")
                        } else { Write-Detail "No se encontró MicrosoftEdgeUpdate.exe."; $script:Failures.Add("WinGet ${id}: sin MicrosoftEdgeUpdate.exe") }
                    } else {
                        Invoke-WinGet uninstall --id $id --exact --silent --disable-interactivity 2>&1 | Out-Null
                        if ($LASTEXITCODE -eq 0) {
                            Invoke-WinGet install --id $id --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 | Out-Null
                            if ($LASTEXITCODE -eq 0) { Write-Detail "Reinstalado en la versión nueva."; $script:Successes.Add("WinGet $id (reinstalado)") }
                            else { Resolve-WinGetFailure -Id $id -Operation install -Details "Reinstalacion fallida: codigo $LASTEXITCODE" }
                        } else {
                            Resolve-WinGetFailure -Id $id -Details "No se pudo desinstalar: codigo $LASTEXITCODE"
                        }
                    }
                } else {
                    Write-Host "FALLO (código $code)" -ForegroundColor Red
                    $packageOutput | Where-Object { $_ -match '\S' } | Select-Object -Last 4 | ForEach-Object { Write-Detail $_.Trim() }
                    Resolve-WinGetFailure -Id $id -Details ("Codigo: $code`n" + ($packageOutput -join [Environment]::NewLine))
                }
            } catch {
                Write-Host 'ERROR' -ForegroundColor Red
                Write-Detail $_.Exception.Message
                Resolve-WinGetFailure -Id $id -Details $_.Exception.Message
            }
        }
    } catch {
        $script:Failures.Add("WinGet: $($_.Exception.Message)")
        Write-ErrMsg "❌ Error en WinGet: $($_.Exception.Message)"
    }
}


# -------------------------
# Microsoft Store
# -------------------------
function Update-MicrosoftStore {
    Write-Section 3 5 'Microsoft Store'
    if ($SkipStore) { Write-WarnMsg "ℹ️ Se solicitó omitir Microsoft Store."; return }
    if ($DryRun) { Write-WarnMsg "ℹ️ DryRun: se omite Microsoft Store."; return }
    if ($ScheduledRun) { Write-WarnMsg "ℹ️ Ejecución programada (SYSTEM, sin sesión de usuario): se omite Microsoft Store."; return }
    if (Get-IsServer) { Write-WarnMsg "ℹ️ Equipo tipo Server: se omite Microsoft Store."; return }

    $storeApp = Get-AppxPackage -Name Microsoft.WindowsStore -ErrorAction SilentlyContinue
    if (-not $storeApp) { Write-ErrMsg "❌ Microsoft Store no está instalada en este sistema."; return }
    if (-not (Test-Internet -VerboseMode)) { Write-ErrMsg "❌ Sin Internet. Omitiendo Store."; return }

    try {
        $wsresetPath = "C:\Windows\System32\wsreset.exe"
        if (Test-Path $wsresetPath) {
            Write-Detail "Limpiando caché de Microsoft Store (wsreset)..."
            Start-Process -FilePath $wsresetPath -NoNewWindow -Wait
        } else {
            Write-WarnMsg "⚠️ wsreset.exe no encontrado; continúo sin limpieza."
        }

        if (Test-WinGetInstalled) {
            Ensure-WinGetSources
            Write-Detail "Actualizando apps Store vía WinGet (msstore)..."
            $wgArgs = @('upgrade','--source','msstore','--all') + @(Get-WinGetUpgradeFlags) + @('--accept-package-agreements','--accept-source-agreements','--silent','--disable-interactivity')
            $storeOut = @(Invoke-WinGet @wgArgs 2>&1 | ForEach-Object { [string]$_ } | Where-Object { $_ -match '\S' -and $_ -notmatch 'msstore. source requires|Terms of Transaction|geographic region' })
            $storeOut | ForEach-Object { Write-Detail $_.Trim() }
            # -1978335212 = "No installed package found" (nada que actualizar en msstore): no es fallo.
            if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1978335212) { $script:Failures.Add("Store (winget msstore): codigo $LASTEXITCODE") }
        } else {
            Write-WarnMsg "⚠️ WinGet no está presente; solo se ejecutó wsreset."
        }
        Write-Ok "✅ Proceso de Microsoft Store finalizado."
    } catch {
        $script:Failures.Add("Store: $($_.Exception.Message)")
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

# -------------------------
# Drivers del fabricante del equipo (HP, Dell, Lenovo) e Intel
# -------------------------
$script:DriverRebootRequired = $false

function Get-DriverWorkFolder {
    param([string]$Name)
    $folder = Join-Path (Join-Path $OutputFolder 'Drivers') $Name
    New-Item -ItemType Directory -Path $folder -Force -ErrorAction Stop | Out-Null
    return $folder
}

function Invoke-DriverProcess {
    param([string]$FilePath, [string[]]$Arguments, [int]$TimeoutSeconds)
    Write-Diag "Ejecutando: `"$FilePath`" $($Arguments -join ' ')"
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -WindowStyle Hidden -ErrorAction Stop
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        try { Stop-Process -Id $process.Id -Force -ErrorAction Stop } catch { Write-WarnMsg "No se pudo detener $(Split-Path $FilePath -Leaf): $($_.Exception.Message)" }
        Write-Diag ("{0} supero {1} s y se detuvo" -f (Split-Path $FilePath -Leaf), $TimeoutSeconds)
        return [pscustomobject]@{ TimedOut=$true; ExitCode=$null }
    }
    Write-Diag ("{0} termino con codigo {1} en {2:N1} s" -f (Split-Path $FilePath -Leaf), $process.ExitCode, $watch.Elapsed.TotalSeconds)
    return [pscustomobject]@{ TimedOut=$false; ExitCode=$process.ExitCode }
}

function Get-InstalledDriverInventory {
    @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop | Where-Object { $_.HardwareID -and $_.DriverVersion } |
        ForEach-Object { [pscustomobject]@{ DeviceName=$_.DeviceName; HardwareId=$_.HardwareID; DriverVersion=$_.DriverVersion } })
}

function Compare-DriverVersion {
    # Devuelve >0 si Left es mayor que Right; $null si alguna version no es comparable.
    param([string]$Left, [string]$Right)
    $a = $null; $b = $null
    if (-not [version]::TryParse($Left, [ref]$a) -or -not [version]::TryParse($Right, [ref]$b)) { return $null }
    return $a.CompareTo($b)
}

function Get-WindowsOsKey {
    # Formato del catalogo de Intel, por ejemplo windows-11-25h2-64.
    $current = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $release = if ($current.DisplayVersion) { $current.DisplayVersion } else { $current.ReleaseId }
    $major = if ([Environment]::OSVersion.Version.Build -ge 22000) { '11' } else { '10' }
    $bits = if ([Environment]::Is64BitOperatingSystem) { '64' } else { '32' }
    return ('windows-{0}-{1}-{2}' -f $major, "$release".ToLower(), $bits)
}

function Get-IntelSilentArguments {
    # Opciones silenciosas documentadas por Intel; /norestart evita el reinicio automatico de Wi-Fi y Bluetooth.
    param([object]$Entry, [string]$Category)
    $catalogOptions = @("$($Entry.InstallOptions)" -split '\s+' | Where-Object { $_ })
    if ($Entry.AllowSilentInstallation -and $catalogOptions.Count) { return $catalogOptions }
    switch ($Category) {
        'Graphics'  { return @('-s') + $catalogOptions }
        'Wireless'  { return @('/quiet','/norestart') }
        'Bluetooth' { return @('/quiet','/norestart') }
    }
    return $null
}

function Get-IntelDriverCatalog {
    # Catalogo publico que usa Intel Driver & Support Assistant; se renueva una vez al dia.
    $folder = Get-DriverWorkFolder 'Intel'
    $zip = Join-Path $folder 'data-en.zip'
    if (-not (Test-Path -LiteralPath $zip) -or (Get-Item -LiteralPath $zip).LastWriteTime -lt (Get-Date).AddDays(-1)) {
        $tmp = "$zip.$([guid]::NewGuid().ToString('N')).download"
        try {
            Invoke-Download -Uri 'https://dsadata.intel.com/data/en' -OutFile $tmp
            Move-Item -LiteralPath $tmp -Destination $zip -Force -ErrorAction Stop
        } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    $extract = Join-Path $folder 'catalog'
    Remove-Item -LiteralPath $extract -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive -LiteralPath $zip -DestinationPath $extract -Force -ErrorAction Stop
    $file = Join-Path $extract 'software-configurations.json'
    if (-not (Test-Path -LiteralPath $file)) { throw 'El catalogo de Intel no incluye software-configurations.json; puede haber cambiado su formato.' }
    return @(Get-Content -LiteralPath $file -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
}

function Find-IntelDriverUpdates {
    # Solo paquetes cuya version de driver supera la instalada: nunca se degrada lo que puso el fabricante del equipo.
    param([object[]]$Catalog, [object[]]$Inventory, [string]$OsKey, [string[]]$SkipIds = @())
    $found = [ordered]@{}
    foreach ($entry in $Catalog) {
        $id = "$($entry.Id)"
        if ($id -in $SkipIds -or $found.Contains($id)) { continue }
        $file = @($entry.Files | Where-Object { $OsKey -in $_.OperatingSystems }) | Select-Object -First 1
        if (-not $file) { continue }
        foreach ($component in @($entry.Components)) {
            if ($component.DetectionType -ne 'Default' -or -not $component.DetectionValues) { continue }
            foreach ($device in $Inventory) {
                if (-not @($component.DetectionValues | Where-Object { $device.HardwareId -like "*$_*" }).Count) { continue }
                $comparison = Compare-DriverVersion -Left $component.Version -Right $device.DriverVersion
                Write-Diag ("Intel {0} '{1}': {2} instalado {3}, catalogo {4} -> {5}" -f $id, $entry.Name, $device.DeviceName, $device.DriverVersion, $component.Version, $(if ($null -eq $comparison) { 'no comparable' } elseif ($comparison -gt 0) { 'mas nuevo' } elseif ($comparison -eq 0) { 'igual' } else { 'mas antiguo, se omite' }))
                if ($comparison -gt 0 -and -not $found.Contains($id)) {
                    $found[$id] = [pscustomobject]@{
                        Id=$id; Name=$entry.Name; Page=$entry.Url; Category=$component.Category
                        DriverVersion=$component.Version; InstalledVersion=$device.DriverVersion
                        Device=$device.DeviceName; HardwareId=$device.HardwareId; File=$file
                        Arguments=(Get-IntelSilentArguments -Entry $entry -Category $component.Category)
                    }
                }
            }
        }
    }
    return @($found.Values)
}

function Install-IntelDriverUpdate {
    param([object]$Update)
    $folder = Get-DriverWorkFolder 'Intel'
    $installer = Join-Path $folder (Split-Path $Update.File.Url -Leaf)
    if (-not (Test-Path -LiteralPath $installer) -or (Get-FileHash -LiteralPath $installer -Algorithm SHA1).Hash -ne $Update.File.Hash) {
        $tmp = "$installer.$([guid]::NewGuid().ToString('N')).download"
        try {
            Invoke-Download -Uri $Update.File.Url -OutFile $tmp
            if ((Get-FileHash -LiteralPath $tmp -Algorithm SHA1).Hash -ne $Update.File.Hash) { throw 'el SHA-1 no coincide con el catalogo de Intel' }
            Move-Item -LiteralPath $tmp -Destination $installer -Force -ErrorAction Stop
        } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    if (-not (Test-DownloadSignature -Path $installer -Publisher 'Intel Corporation')) { throw 'el instalador no tiene una firma valida de Intel Corporation' }
    $result = Invoke-DriverProcess -FilePath $installer -Arguments $Update.Arguments -TimeoutSeconds $script:UpdaterConfig.Drivers.InstallTimeoutSeconds
    if ($result.TimedOut) { return [pscustomobject]@{ Status='Failed'; Detail='tiempo agotado' } }
    # Exito solo si el driver del dispositivo alcanza la version del catalogo, como en RuckZuck.
    $device = @(Get-InstalledDriverInventory | Where-Object { $_.HardwareId -eq $Update.HardwareId }) | Select-Object -First 1
    $confirmed = $device -and (Compare-DriverVersion -Left $device.DriverVersion -Right $Update.DriverVersion) -ge 0
    if ($confirmed) {
        Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
        return [pscustomobject]@{ Status='Installed'; Detail="version $($device.DriverVersion)" }
    }
    if ($result.ExitCode -in @(3010,1641)) {
        Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
        return [pscustomobject]@{ Status='RebootRequired'; Detail='se aplica al reiniciar' }
    }
    return [pscustomobject]@{ Status='Failed'; Detail="codigo $($result.ExitCode) sin cambio de version" }
}

function Update-IntelDrivers {
    Write-Detail 'Intel: consultando el catalogo de Intel Driver & Support Assistant...'
    try {
        $updates = @(Find-IntelDriverUpdates -Catalog (Get-IntelDriverCatalog) -Inventory (Get-InstalledDriverInventory) -OsKey (Get-WindowsOsKey) -SkipIds $script:UpdaterConfig.Drivers.SkipIntelIds)
    } catch {
        $script:Failures.Add("Drivers Intel: $($_.Exception.Message)")
        Write-ErrMsg "    ❌ Catalogo de Intel: $($_.Exception.Message)"
        return
    }
    if ($updates.Count -eq 0) { Write-Ok '    ✅ Intel: los drivers detectados estan al dia.'; return }
    Write-WarnMsg ("    📋 Intel: actualizaciones disponibles: {0}" -f $updates.Count)
    foreach ($update in $updates) {
        $label = "$($update.Name) ($($update.InstalledVersion) → $($update.DriverVersion))"
        if ($DryRun) { Write-Host "      • $label" -ForegroundColor White; continue }
        if (-not $update.Arguments) {
            Write-WarnMsg "    ⚠️ ${label}: sin instalacion silenciosa verificada; descargar en $($update.Page)"
            $script:Skipped.Add("Intel $($update.Name): sin instalacion silenciosa verificada")
            continue
        }
        Write-Host "    $label ... " -NoNewline:(-not $script:DiagMode) -ForegroundColor White
        try { $result = Install-IntelDriverUpdate -Update $update } catch { $result = [pscustomobject]@{ Status='Failed'; Detail=$_.Exception.Message } }
        switch ($result.Status) {
            'Installed' { Write-Host 'OK' -ForegroundColor Green; $script:Successes.Add("Intel $($update.Name): $($result.Detail)") }
            'RebootRequired' { Write-Host 'REINICIO PENDIENTE' -ForegroundColor Yellow; $script:DriverRebootRequired = $true; $script:Successes.Add("Intel $($update.Name): $($result.Detail)") }
            default { Write-Host 'FALLO' -ForegroundColor Red; Write-Detail $result.Detail; $script:Failures.Add("Intel $($update.Name): $($result.Detail)") }
        }
    }
}

function Get-OemVendor {
    $manufacturer = "$((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Manufacturer)"
    # \b deja fuera a HPE (servidores ProLiant), que HP Image Assistant no admite.
    if ($manufacturer -match '^(HP|Hewlett-Packard)\b') { return 'HP' }
    if ($manufacturer -match '^Dell') { return 'Dell' }
    if ($manufacturer -match '^Lenovo') { return 'Lenovo' }
    return $null
}

function Test-OnAcPower {
    # BatteryStatus 1 = descargando; un equipo sin bateria se considera conectado.
    return -not @(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue | Where-Object { $_.BatteryStatus -eq 1 }).Count
}

function Suspend-BitLockerForFirmware {
    # WMI en lugar de Get-BitLockerVolume: funciona en pwsh 7 y no depende del idioma de manage-bde.
    $volume = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$env:SystemDrive'" -ErrorAction SilentlyContinue
    if (-not $volume -or $volume.ProtectionStatus -ne 1) { return }
    $result = Invoke-CimMethod -InputObject $volume -MethodName DisableKeyProtectors -Arguments @{ DisableCount = [uint32]1 } -ErrorAction Stop
    if ($result.ReturnValue -ne 0) { throw "no se pudo suspender BitLocker (codigo $($result.ReturnValue))" }
    Write-WarnMsg '    🔓 BitLocker suspendido hasta el proximo reinicio para actualizar BIOS/firmware.'
}

function Get-HPImageAssistant {
    # Se descarga con WinGet (verifica SHA-256) y se extrae en Drivers\HPIA; no se instala en el sistema.
    $folder = Get-DriverWorkFolder 'HPIA'
    $tool = Join-Path $folder 'tool'
    $stamp = Join-Path $folder 'descargado.txt'
    $exe = Get-ChildItem -LiteralPath $tool -Filter 'HPImageAssistant.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    $fresh = (Test-Path -LiteralPath $stamp) -and (Get-Item -LiteralPath $stamp).LastWriteTime -gt (Get-Date).AddDays(-30)
    if ($exe -and ($fresh -or $DryRun -or -not $script:UpdaterConfig.Drivers.InstallVendorTool)) { return $exe.FullName }
    if ($DryRun -or -not $script:UpdaterConfig.Drivers.InstallVendorTool) { return $null }
    $download = Join-Path $folder 'descarga'
    Remove-Item -LiteralPath $download -Recurse -Force -ErrorAction SilentlyContinue
    Write-Detail 'HP: descargando HP Image Assistant con WinGet...'
    Invoke-WinGet download --id HP.ImageAssistant --exact --source winget --download-directory $download --accept-source-agreements --accept-package-agreements | Out-Null
    $installer = Get-ChildItem -LiteralPath $download -Filter '*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $installer) { throw "WinGet no descargo HP Image Assistant (codigo $LASTEXITCODE)." }
    if (-not (Test-DownloadSignature -Path $installer.FullName -Publisher 'HP Inc.')) { throw 'HP Image Assistant no tiene una firma valida de HP Inc.' }
    Remove-Item -LiteralPath $tool -Recurse -Force -ErrorAction SilentlyContinue
    # Los SoftPaq de HP terminan con 1168 al solo extraer; se valida por el ejecutable resultante.
    Invoke-DriverProcess -FilePath $installer.FullName -Arguments @('/s','/e','/f',"`"$tool`"") -TimeoutSeconds 600 | Out-Null
    $exe = Get-ChildItem -LiteralPath $tool -Filter 'HPImageAssistant.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $exe) { throw 'No se pudo extraer HP Image Assistant.' }
    Set-Content -LiteralPath $stamp -Value (Get-Date -Format s)
    Remove-Item -LiteralPath $download -Recurse -Force -ErrorAction SilentlyContinue
    return $exe.FullName
}

function Get-HPImageAssistantRecommendations {
    param([string]$ReportFolder)
    $xmlFile = Get-ChildItem -LiteralPath $ReportFolder -Filter '*.xml' -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $xmlFile) { return @() }
    [xml]$xml = Get-Content -LiteralPath $xmlFile.FullName -Raw -ErrorAction Stop
    foreach ($category in @('Drivers','BIOS','Firmware')) {
        foreach ($item in @($xml.HPIA.Recommendations.$category.Recommendation)) {
            if (-not $item) { continue }
            [pscustomobject]@{ Category=$category; Component=$item.TargetComponent; Installed=$item.TargetVersion; Available=$item.ReferenceVersion; SoftPaq=$item.Solution.Softpaq.Id; Name=$item.Solution.Softpaq.Name }
        }
    }
}

function Invoke-HPImageAssistant {
    param([string]$Executable, [string[]]$Categories, [ValidateSet('List','Install')][string]$Action)
    $report = Join-Path (Join-Path $LogFolder 'HPIA') ('{0:yyyyMMdd-HHmmss}-{1}' -f (Get-Date), $Action)
    New-Item -ItemType Directory -Path $report -Force -ErrorAction Stop | Out-Null
    $softpaqs = Get-DriverWorkFolder 'HPIA\softpaqs'
    $arguments = @('/Operation:Analyze', "/Category:$($Categories -join ',')", '/Selection:All', "/Action:$Action", '/Silent', '/Noninteractive', "/ReportFolder:`"$report`"", "/SoftpaqDownloadFolder:`"$softpaqs`"")
    $result = Invoke-DriverProcess -FilePath $Executable -Arguments $arguments -TimeoutSeconds $script:UpdaterConfig.Drivers.InstallTimeoutSeconds
    return [pscustomobject]@{ TimedOut=$result.TimedOut; ExitCode=$result.ExitCode; Report=$report; Recommendations=@(Get-HPImageAssistantRecommendations -ReportFolder $report) }
}

function Update-HPDrivers {
    param([bool]$Firmware)
    $exe = Get-HPImageAssistant
    if (-not $exe) { Write-Info '    HP Image Assistant no esta disponible (DryRun o InstallVendorTool=false); se omite.'; $script:Skipped.Add('Drivers HP: sin HP Image Assistant'); return }
    $categories = @('Drivers') + $(if ($Firmware) { @('BIOS','Firmware') } else { @() })
    # HPIA: 0 correcto, 256/257 sin recomendaciones, 3010 requiere reinicio; el resto es fallo.
    $analysis = Invoke-HPImageAssistant -Executable $exe -Categories $categories -Action List
    if ($analysis.TimedOut -or $analysis.ExitCode -notin @(0,256,257)) { throw "analisis de HP Image Assistant fallo (codigo $($analysis.ExitCode)); reporte: $($analysis.Report)" }
    if ($analysis.Recommendations.Count -eq 0) { Write-Ok '    ✅ HP: drivers, BIOS y firmware al dia.'; return }
    Write-WarnMsg ("    📋 HP: actualizaciones disponibles: {0}" -f $analysis.Recommendations.Count)
    $analysis.Recommendations | ForEach-Object { Write-Host ("      • [{0}] {1} ({2} → {3}) {4}" -f $_.Category, $_.Name, $_.Installed, $_.Available, $_.SoftPaq) -ForegroundColor White }
    if ($DryRun) { return }
    if (@($analysis.Recommendations | Where-Object { $_.Category -ne 'Drivers' }).Count) { Suspend-BitLockerForFirmware }
    $install = Invoke-HPImageAssistant -Executable $exe -Categories $categories -Action Install
    if ($install.TimedOut) { throw "HP Image Assistant supero el tiempo limite; reporte: $($install.Report)" }
    switch ($install.ExitCode) {
        { $_ -in @(0,256,257) } { Write-Ok '    ✅ HP: actualizaciones instaladas.'; $script:Successes.Add("Drivers HP ($($analysis.Recommendations.Count))") }
        3010 { Write-WarnMsg '    ✅ HP: actualizaciones instaladas; requiere reinicio.'; $script:DriverRebootRequired = $true; $script:Successes.Add("Drivers HP ($($analysis.Recommendations.Count), reinicio pendiente)") }
        default {
            # Los install.cmd de los SoftPaq llaman a HPUP.exe sin ruta: con esta variable de seguridad activa terminan con 9009.
            $hint = if ($env:NoDefaultCurrentDirectoryInExePath) { ' NoDefaultCurrentDirectoryInExePath esta activa en este proceso y los SoftPaq que llaman a HPUP.exe sin ruta fallan con 9009; ejecute el script desde una consola sin esa variable.' } else { '' }
            throw "HP Image Assistant termino con codigo $($install.ExitCode); reporte: $($install.Report).$hint"
        }
    }
}

function Get-DellCommandUpdateCli {
    $paths = @("$env:ProgramFiles\Dell\CommandUpdate\dcu-cli.exe", "${env:ProgramFiles(x86)}\Dell\CommandUpdate\dcu-cli.exe")
    $found = $paths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($found -or $DryRun -or -not $script:UpdaterConfig.Drivers.InstallVendorTool) { return $found }
    Write-Detail 'Dell: instalando Dell Command | Update con WinGet...'
    Invoke-WinGet install --id Dell.CommandUpdate --exact --silent --source winget --accept-source-agreements --accept-package-agreements | Out-Null
    return ($paths | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1)
}

function Update-DellDrivers {
    param([bool]$Firmware)
    $cli = Get-DellCommandUpdateCli
    if (-not $cli) { Write-Info '    Dell Command | Update no esta disponible; se omite.'; $script:Skipped.Add('Drivers Dell: sin Dell Command | Update'); return }
    $types = (@('driver') + $(if ($Firmware) { @('bios','firmware') } else { @() })) -join ','
    $log = Join-Path $LogFolder ('DellCommandUpdate-{0:yyyyMMdd-HHmmss}.log' -f (Get-Date))
    $arguments = if ($DryRun) { @('/scan', "-updateType=$types", "-outputLog=`"$log`"") } else { @('/applyUpdates', "-updateType=$types", '-reboot=disable', '-autoSuspendBitLocker=enable', "-outputLog=`"$log`"") }
    $result = Invoke-DriverProcess -FilePath $cli -Arguments $arguments -TimeoutSeconds $script:UpdaterConfig.Drivers.InstallTimeoutSeconds
    if ($result.TimedOut) { throw "Dell Command | Update supero el tiempo limite; log: $log" }
    # dcu-cli: 0 correcto, 1 requiere reinicio, 5 reinicio previo pendiente, 500 sin actualizaciones.
    switch ($result.ExitCode) {
        0 { Write-Ok "    ✅ Dell: proceso completado. Log: $log"; if (-not $DryRun) { $script:Successes.Add('Drivers Dell') } }
        1 { Write-WarnMsg '    ✅ Dell: actualizaciones instaladas; requiere reinicio.'; $script:DriverRebootRequired = $true; $script:Successes.Add('Drivers Dell (reinicio pendiente)') }
        5 { Write-WarnMsg '    ⚠️ Dell: hay un reinicio pendiente de una actualizacion anterior.'; $script:DriverRebootRequired = $true; $script:Skipped.Add('Drivers Dell: reinicio pendiente antes de continuar') }
        500 { Write-Ok '    ✅ Dell: drivers, BIOS y firmware al dia.' }
        default { throw "Dell Command | Update termino con codigo $($result.ExitCode); log: $log" }
    }
}

function Update-LenovoDrivers {
    param([bool]$Firmware)
    if (-not (Get-Module -ListAvailable -Name LSUClient)) {
        if ($DryRun -or -not $script:UpdaterConfig.Drivers.InstallVendorTool) { Write-Info '    Modulo LSUClient no disponible; se omite.'; $script:Skipped.Add('Drivers Lenovo: sin LSUClient'); return }
        Ensure-NuGetProvider
        Write-Detail 'Lenovo: instalando el modulo LSUClient...'
        Install-Module LSUClient -Scope $(if (Test-IsAdmin) { 'AllUsers' } else { 'CurrentUser' }) -Force -ErrorAction Stop
    }
    Import-Module LSUClient -ErrorAction Stop
    $types = @('Driver') + $(if ($Firmware) { @('BIOS','Firmware') } else { @() })
    $updates = @(Get-LSUpdate -ErrorAction Stop | Where-Object { "$($_.Type)" -in $types -and $_.Installer.Unattended })
    if ($updates.Count -eq 0) { Write-Ok '    ✅ Lenovo: drivers, BIOS y firmware al dia.'; return }
    Write-WarnMsg ("    📋 Lenovo: actualizaciones disponibles: {0}" -f $updates.Count)
    $updates | ForEach-Object { Write-Host ("      • [{0}] {1} {2}" -f $_.Type, $_.Title, $_.Version) -ForegroundColor White }
    if ($DryRun) { return }
    if (@($updates | Where-Object { "$($_.Type)" -ne 'Driver' }).Count) { Suspend-BitLockerForFirmware }
    $results = @($updates | Install-LSUpdate -ErrorAction Stop)
    $failed = @($results | Where-Object { -not $_.Success })
    if (@($results | Where-Object { "$($_.PendingAction)" -match 'REBOOT|SHUTDOWN' }).Count) { $script:DriverRebootRequired = $true }
    if ($failed.Count) { throw "Lenovo: fallaron $($failed.Count) de $($results.Count) actualizaciones: $(($failed | ForEach-Object { $_.Title }) -join ', ')" }
    Write-Ok "    ✅ Lenovo: $($results.Count) actualizaciones instaladas."
    $script:Successes.Add("Drivers Lenovo ($($results.Count))")
}

function Update-OemDrivers {
    $vendor = Get-OemVendor
    if (-not $vendor) {
        Write-Info '    El fabricante del equipo no es HP, Dell ni Lenovo; se omite su herramienta.'
        return
    }
    $firmware = $script:UpdaterConfig.Drivers.IncludeFirmware
    if ($firmware -and -not (Test-OnAcPower)) {
        Write-WarnMsg '    ⚠️ Equipo con bateria: se omiten BIOS y firmware; conecte el cargador para incluirlos.'
        $script:Skipped.Add("BIOS/firmware ${vendor}: equipo sin corriente alterna")
        $firmware = $false
    }
    Write-Detail "Fabricante del equipo: $vendor$(if ($firmware) { ' (drivers, BIOS y firmware)' } else { ' (drivers)' })"
    switch ($vendor) {
        'HP' { Update-HPDrivers -Firmware $firmware }
        'Dell' { Update-DellDrivers -Firmware $firmware }
        'Lenovo' { Update-LenovoDrivers -Firmware $firmware }
    }
}

function Get-PciDeviceName {
    # pci.ids (pciutils, GPL-2+/BSD-3) solo nombra dispositivos; no aporta drivers.
    param([string]$HardwareId)
    if ($HardwareId -notmatch 'VEN_([0-9A-F]{4})&DEV_([0-9A-F]{4})') { return $null }
    $vendorId = $Matches[1].ToLower(); $deviceId = $Matches[2].ToLower()
    if (-not $script:PciIds) {
        $file = Join-Path (Get-DriverWorkFolder 'pci') 'pci.ids'
        if (-not (Test-Path -LiteralPath $file) -or (Get-Item -LiteralPath $file).LastWriteTime -lt (Get-Date).AddDays(-30)) {
            Invoke-Download -Uri 'https://raw.githubusercontent.com/pciutils/pciids/master/pci.ids' -OutFile $file
        }
        $script:PciIds = Get-Content -LiteralPath $file -ErrorAction Stop
    }
    $vendorName = $null
    foreach ($line in $script:PciIds) {
        if ($null -eq $vendorName) {
            if ($line -match "^$vendorId\s+(.+)$") { $vendorName = $Matches[1] }
        } elseif ($line -match "^\t$deviceId\s+(.+)$") {
            return "$vendorName $($Matches[1])"
        } elseif ($line -match '^[0-9a-f]{4}\s') { break }
    }
    return $vendorName
}

function Write-DevicesWithoutDriver {
    # Codigo 28: el dispositivo no tiene driver instalado. Solo se informa.
    $missing = @(Get-CimInstance Win32_PnPEntity -ErrorAction Stop | Where-Object { $_.ConfigManagerErrorCode -eq 28 })
    foreach ($device in $missing) {
        $hardwareId = @($device.HardwareID)[0]
        $name = $null
        try { $name = Get-PciDeviceName -HardwareId $hardwareId } catch { Write-Detail "pci.ids no disponible: $($_.Exception.Message)" }
        if (-not $name) { $name = $device.Name }
        Write-WarnMsg "    ⚠️ Sin driver: $name ($hardwareId)"
        $script:Skipped.Add("Sin driver: $name ($hardwareId)")
    }
}

function Update-VendorDrivers {
    Write-Section 4 5 'Drivers del fabricante e Intel'
    $sources = @($script:UpdaterConfig.Drivers.Sources)
    if (-not @($sources | Where-Object { $_ -in @('Oem','Intel') }).Count) { Write-Info '    Fuentes Oem e Intel desactivadas en la configuracion.'; return }
    # HP Image Assistant, Dell Command | Update, LSUClient y el catalogo de Intel son para equipos cliente.
    if (Get-IsServer) {
        Write-Info '    Windows Server: los drivers se actualizan con Windows Update (paso 5); las herramientas de cliente no aplican a servidores.'
        return
    }
    if (-not (Test-IsAdmin)) {
        Write-WarnMsg '    ⚠️ Se requiere administrador para instalar drivers; se omite este paso.'
        $script:Skipped.Add('Drivers del fabricante e Intel: sin permisos de administrador')
        return
    }
    if (-not (Test-Internet -VerboseMode)) { Write-ErrMsg '    ❌ Sin Internet. Omitiendo drivers del fabricante e Intel.'; return }
    if ($sources -contains 'Oem') {
        try { Update-OemDrivers } catch { $script:Failures.Add("Drivers del fabricante: $($_.Exception.Message)"); Write-ErrMsg "    ❌ Fabricante del equipo: $($_.Exception.Message)" }
    }
    if ($sources -contains 'Intel') { Update-IntelDrivers }
    try { Write-DevicesWithoutDriver } catch { Write-WarnMsg "    ⚠️ No se pudo revisar dispositivos sin driver: $($_.Exception.Message)" }
}

function Get-UniqueWindowsUpdates {
    # PSWindowsUpdate devuelve el mismo update en cada etapa (aceptar, descargar, instalar); se conserva el ultimo estado.
    param([object[]]$Updates)
    @($Updates | Where-Object { $_ } | Group-Object { "$($_.KB)|$($_.Title)" } | ForEach-Object { $_.Group[-1] })
}

function Update-WindowsDriversAndUpdates {
    Write-Section 5 5 'Windows Update (sistema y drivers)'
    if (-not (Test-IsAdmin)) { Write-WarnMsg "ℹ️ Ejecuta como Administrador para aplicar Windows Update sin restricciones."; }
    if (-not (Test-Internet -VerboseMode)) { Write-ErrMsg "❌ Sin Internet. Abortando Windows Update."; return }

    # PSWindowsUpdate
    try {
        Ensure-NuGetProvider
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-WarnMsg "📥 Instalando módulo PSWindowsUpdate..."
            # AllUsers (si hay admin): bajo SYSTEM, CurrentUser iria al perfil de SYSTEM.
            $moduleScope = if (Test-IsAdmin) { 'AllUsers' } else { 'CurrentUser' }
            Install-Module PSWindowsUpdate -Scope $moduleScope -Force -AllowClobber -ErrorAction Stop
        }
        Import-Module PSWindowsUpdate -ErrorAction Stop
        # Sin la fuente WindowsUpdate en Drivers.Sources, Windows Update solo aplica parches del sistema.
        $wuFilter = @{}
        if ($script:UpdaterConfig.Drivers.Sources -notcontains 'WindowsUpdate') {
            $wuFilter.NotCategory = 'Drivers'
            Write-Detail 'Drivers excluidos de Windows Update por configuracion.'
        }

        if ($DryRun) {
            Write-Info "🔍 DryRun: actualizaciones de Windows pendientes (no se instalan)..."
            Get-WindowsUpdate -MicrosoftUpdate @wuFilter | Format-Table -AutoSize | Out-String | Write-Host
        } else {
            Write-Detail "Buscando e instalando actualizaciones..."
            $wuResult = $null
            try {
                $wuResult = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -IgnoreReboot @wuFilter -ErrorAction Stop
            } catch {
                # Solo si falla se reinician los servicios y se reintenta una vez.
                Write-WarnMsg "⚠️ Falló Windows Update ($($_.Exception.Message)); reinicio servicios y reintento una vez..."
                foreach ($s in @('wuauserv','cryptsvc')) {
                    try { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue; Start-Service -Name $s -ErrorAction Stop }
                    catch { Write-WarnMsg ("⚠️ No se pudo reiniciar {0}: {1}" -f $s, $_.Exception.Message) }
                }
                $wuResult = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -IgnoreReboot @wuFilter -ErrorAction Stop
            }
            $wuResult = Get-UniqueWindowsUpdates -Updates $wuResult
            if ($wuResult) {
                Write-WarnMsg ("📋 Actualizaciones procesadas: {0}" -f @($wuResult).Count)
                ($wuResult | Format-Table KB, Status, Size, Title -AutoSize | Out-String -Width 200).TrimEnd().Split("`n") | Where-Object { $_.Trim() } |
                    ForEach-Object { Write-Host "  $($_.TrimEnd())" -ForegroundColor White }
                $script:Successes.Add("Windows Update ($(@($wuResult).Count))")
            } else {
                Write-Ok "✅ No hay actualizaciones de Windows pendientes."
            }
        }
    } catch {
        $script:Failures.Add("Windows Update: $($_.Exception.Message)")
        Write-ErrMsg "❌ Error con PSWindowsUpdate: $($_.Exception.Message)"
    }

    if (Get-PendingReboot) {
        Write-WarnMsg "⚠️ Se requiere reiniciar el sistema para aplicar cambios."
        if ($RebootPolicy -eq 'IfPending' -and -not $DryRun) {
            Write-WarnMsg "🔁 RebootPolicy=IfPending: el equipo se reiniciará en 60 segundos (cancelar: shutdown /a)."
            $script:RebootScheduled = $true
        }
    } else { Write-Ok "✅ No es necesario reiniciar." }
}

# Chequeo de reinicio pendiente
function Get-PendingReboot {
    # Algunos instaladores de drivers piden reinicio sin dejar estas claves.
    if ($script:DriverRebootRequired) { Write-Diag 'Reinicio pendiente: lo pidio un instalador de drivers.'; return $true }
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations'
    )
    foreach ($k in $keys) { if (Test-Path $k) { Write-Diag "Reinicio pendiente: existe $k"; return $true } }
    return $false
}

function Read-UpdaterYesNo {
    param([string]$Prompt)
    do { $answer = (Read-Host "$Prompt [S/N]").Trim() } while ($answer -notmatch '^(s|si|n|no)$')
    return ($answer -match '^(s|si)$')
}

function Configure-UpdaterScheduledTask {
    if ($ScheduledRun -or $SkipScheduleTask -or $DryRun) { return }
    $configuredSchedule = $script:UpdaterConfig.Schedule.Enabled
    if (-not $configuredSchedule) {
        if (-not $script:UpdaterConfig.AskQuestions -or -not [Environment]::UserInteractive) { return }
        if (-not (Read-UpdaterYesNo 'Desea crear una tarea automatica semanal para este script?')) {
            $script:UpdaterConfig.AskQuestions = $false
            try { Save-UpdaterConfiguration } catch { Write-WarnMsg "No se pudo guardar la configuracion: $($_.Exception.Message)" }
            return
        }
    }
    if (-not (Test-IsAdmin)) {
        Write-WarnMsg 'Ejecute como Administrador para crear la tarea programada.'
        return
    }
    try {
        $taskName = Get-UpdaterTaskName
        $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if (-not $configuredSchedule -and $existing -and -not (Read-UpdaterYesNo "La tarea $taskName ya existe. Desea reemplazar su horario?")) { return }
        $days = @('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')
        if ($configuredSchedule) {
            $day = [array]::IndexOf($days, [string]$script:UpdaterConfig.Schedule.DayOfWeek) + 1
            $time = $script:UpdaterConfig.Schedule.Time
        } else {
        Write-Info 'Dia semanal: 1=Lunes, 2=Martes, 3=Miercoles, 4=Jueves, 5=Viernes, 6=Sabado, 7=Domingo.'
        do { $day = (Read-Host 'Seleccione el dia (1-7)').Trim() } while ($day -notmatch '^[1-7]$')
        do { $time = (Read-Host 'Hora local del equipo en formato HH:mm (ejemplo 22:30)').Trim() } while ($time -notmatch '^([01][0-9]|2[0-3]):[0-5][0-9]$')
        }
        Register-UpdaterScheduledTask -DayOfWeek $days[[int]$day - 1] -Time $time -Replace:([bool]$existing) | Out-Null
        if (-not $configuredSchedule) { $script:UpdaterConfig.AskQuestions = $false }
        Save-UpdaterConfiguration
    } catch { Write-ErrMsg "No se pudo crear la tarea programada: $($_.Exception.Message)" }
}

function Get-UpdaterTaskName {
    # Un nombre por ruta del script: varias copias de la 8.1 en un equipo no se pisan.
    $scriptPath = $script:UpdaterScriptPath
    if (-not $scriptPath -or -not (Test-Path -LiteralPath $scriptPath)) { throw 'Se requiere ejecutar el script desde un archivo guardado.' }
    $hashAlgorithm = [Security.Cryptography.SHA256]::Create()
    try { $pathHash = [BitConverter]::ToString($hashAlgorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($scriptPath.ToLowerInvariant()))).Replace('-', '').Substring(0, 12) }
    finally { $hashAlgorithm.Dispose() }
    return "UpdateAppsDrivers8.1-$pathHash"
}

function Register-UpdaterScheduledTask {
    # Registra la tarea semanal de esta copia y guarda el horario en el JSON (sin escribir el archivo).
    param([string]$DayOfWeek, [string]$Time, [switch]$Replace)
    $scriptPath = $script:UpdaterScriptPath
    $taskName = Get-UpdaterTaskName
    $pwshPath = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
    if (-not (Test-Path -LiteralPath $pwshPath)) {
        $command = Get-Command pwsh.exe -ErrorAction SilentlyContinue
        if (-not $command) { throw 'PowerShell 7 debe estar instalado antes de programar la tarea.' }
        $pwshPath = $command.Source
    }
    $days = @('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')
    $dayNames = @('Lunes','Martes','Miercoles','Jueves','Viernes','Sabado','Domingo')
    $dayName = $dayNames[[array]::IndexOf($days, $DayOfWeek)]
    $at = [datetime]::Today.Add([TimeSpan]::ParseExact($Time, 'hh\:mm', [Globalization.CultureInfo]::InvariantCulture))
    Write-Info "La tarea se ejecutara como SYSTEM cada $dayName a las $Time, con instalacion automatica de WinGet si falta."
    $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -ScheduledRun -OutputFolder "{1}"' -f $scriptPath, $OutputFolder.TrimEnd('\')
    # Leer SkipStore del JSON en cada ejecucion, sin fijarlo en los argumentos de la tarea.
    if ($IncludePinned) { $arguments += ' -IncludePinned' }
    if ($IncludeUnknown) { $arguments += ' -IncludeUnknown' }
    if ($AllowReinstall) { $arguments += ' -AllowReinstall' }
    if ($ExcludeIds.Count -gt 0) { $arguments += (' -ExcludeIds "{0}"' -f ($ExcludeIds -join ',')) }
    $arguments += " -RebootPolicy $RebootPolicy -LogRetentionDays $LogRetentionDays"
    $action = New-ScheduledTaskAction -Execute $pwshPath -Argument $arguments -WorkingDirectory (Split-Path -Parent $scriptPath) -ErrorAction Stop
    $trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek $DayOfWeek -At $at -ErrorAction Stop
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest -ErrorAction Stop
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Hours 4) -ErrorAction Stop
    $registration = @{ TaskName=$taskName; Action=$action; Trigger=$trigger; Principal=$principal; Settings=$settings; Description="Actualizaciones semanales de aplicaciones y drivers: $scriptPath"; ErrorAction='Stop' }
    if ($Replace) { $registration.Force = $true }
    Register-ScheduledTask @registration | Out-Null
    $script:UpdaterConfig.SkipStore = [bool]$SkipStore
    $script:UpdaterConfig.Schedule.Enabled = $true
    $script:UpdaterConfig.Schedule.DayOfWeek = $DayOfWeek
    $script:UpdaterConfig.Schedule.Time = $Time
    Write-Ok "Tarea $taskName creada: $dayName a las $Time (horario local). Conserve el script en $scriptPath."
    return $taskName
}

function Get-LegacyUpdaterTasks {
    # Tareas de versiones anteriores: DailyUpdateAppsDrivers (CreateTask.ps1) o acciones hacia UpdateAppsDrivers*.ps1 que no son la 8.1.
    @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
        $task = $_
        if ($task.TaskName -eq 'DailyUpdateAppsDrivers') { return $true }
        foreach ($action in @($task.Actions)) {
            foreach ($match in [regex]::Matches("$($action.Execute) $($action.Arguments)", '(?i)UpdateAppsDrivers[\w.\-]*\.ps1')) {
                if ($match.Value -ine 'UpdateAppsDrivers8.1.ps1') { return $true }
            }
        }
        return $false
    })
}

function Get-LegacyTaskSchedule {
    # Semanal con un dia: ese dia y hora. Diaria u otra: su hora con el dia del JSON, porque el uso acordado es semanal.
    param([object]$Task)
    $days = @('Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday')
    $trigger = @($Task.Triggers | Where-Object { $_.StartBoundary }) | Select-Object -First 1
    $day = [string]$script:UpdaterConfig.Schedule.DayOfWeek
    $time = [string]$script:UpdaterConfig.Schedule.Time
    if ($trigger) {
        $start = [datetime]::MinValue
        if ([datetime]::TryParse([string]$trigger.StartBoundary, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$start)) { $time = $start.ToString('HH:mm') }
        # DaysOfWeek de MSFT_TaskWeeklyTrigger es una mascara: domingo=1, lunes=2 ... sabado=64.
        $mask = [int]$trigger.DaysOfWeek
        $selected = @(0..6 | Where-Object { $mask -band (1 -shl $_) })
        if ($selected.Count -eq 1) { $day = $days[$selected[0]] }
    }
    return [pscustomobject]@{ DayOfWeek=$day; Time=$time }
}

function Invoke-LegacyTaskMigration {
    # Crea (o conserva) la tarea de la 8.1, la verifica y despues elimina las tareas de versiones anteriores.
    if (-not (Test-IsAdmin)) { return }
    try { $legacy = @(Get-LegacyUpdaterTasks) } catch { Write-WarnMsg "No se pudieron revisar tareas anteriores: $($_.Exception.Message)"; return }
    Write-Diag ("Tareas de versiones anteriores encontradas: {0}" -f $legacy.Count)
    foreach ($task in $legacy) { Write-Diag ("  {0}{1}: {2}" -f $task.TaskPath, $task.TaskName, (($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ')) }
    if ($legacy.Count -eq 0) { return }
    Write-WarnMsg ("⚠️ Tareas de versiones anteriores del script: {0}" -f (($legacy | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" }) -join ', '))
    try {
        $taskName = Get-UpdaterTaskName
        $current = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($DryRun) {
            $plan = if ($current) { "se conservaria $taskName" } else { $schedule = Get-LegacyTaskSchedule -Task $legacy[0]; "se crearia $taskName ($($schedule.DayOfWeek) $($schedule.Time))" }
            Write-Info "    DryRun: $plan y se eliminarian las tareas anteriores."
            return
        }
        if (-not $current) {
            $schedule = Get-LegacyTaskSchedule -Task $legacy[0]
            Register-UpdaterScheduledTask -DayOfWeek $schedule.DayOfWeek -Time $schedule.Time | Out-Null
            Save-UpdaterConfiguration
            if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) { throw "no se encontro $taskName despues de crearla" }
        }
        foreach ($task in $legacy) {
            Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -Confirm:$false -ErrorAction Stop
            Write-Ok "✅ Tarea anterior eliminada: $($task.TaskPath)$($task.TaskName)"
            $script:Successes.Add("Tarea anterior migrada: $($task.TaskName)")
        }
    } catch {
        $script:Failures.Add("Migracion de tareas anteriores: $($_.Exception.Message)")
        Write-ErrMsg "❌ No se migraron las tareas anteriores (se conservan): $($_.Exception.Message)"
    }
}

function Write-DiagnosticContext {
    # Contexto para comparar equipos y reproducir fallos; el SHA-256 identifica la version exacta del script.
    if (-not $script:DiagMode) { return }
    Write-Diag "Script: $($script:UpdaterScriptPath)"
    try { Write-Diag "SHA-256 del script: $((Get-FileHash -LiteralPath $script:UpdaterScriptPath -Algorithm SHA256 -ErrorAction Stop).Hash)" } catch { Write-Diag "SHA-256 del script no disponible: $($_.Exception.Message)" }
    Write-Diag "PowerShell $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition)), proceso de $(if ([Environment]::Is64BitProcess) { 64 } else { 32 }) bits"
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $ubr = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).UBR
        Write-Diag "Windows: $($os.Caption) $($os.Version).$ubr; servidor: $(Get-IsServer)"
        $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        Write-Diag "Equipo: $($computer.Manufacturer) $($computer.Model)"
    } catch { Write-Diag "No se pudo leer el sistema: $($_.Exception.Message)" }
    Write-Diag "Usuario: $([Security.Principal.WindowsIdentity]::GetCurrent().Name); admin: $(Test-IsAdmin); programado: $([bool]$ScheduledRun); DryRun: $([bool]$DryRun)"
    Write-Diag "OutputFolder: $OutputFolder; RebootPolicy: $RebootPolicy; politica de ejecucion: $(Get-ExecutionPolicy)"
    Write-Diag "Configuracion efectiva: $($script:UpdaterConfig | ConvertTo-Json -Depth 6 -Compress)"
    try {
        $target = [uri]'https://www.microsoft.com'
        $proxy = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($target)
        Write-Diag "Proxy para ${target}: $(if (-not $proxy -or $proxy -eq $target) { 'sin proxy' } else { $proxy })"
    } catch { Write-Diag "Proxy no disponible: $($_.Exception.Message)" }
    Write-Diag "NoDefaultCurrentDirectoryInExePath: $(if ($env:NoDefaultCurrentDirectoryInExePath) { 'activa (los SoftPaq de HP que llaman a HPUP.exe sin ruta fallan con 9009)' } else { 'no definida' })"
    if (-not (Get-PendingReboot)) { Write-Diag 'Sin reinicio pendiente al iniciar.' }
}

# -------------------------
# MAIN
# -------------------------
Write-Host ''
Write-Host ('█' * 70) -ForegroundColor Cyan
Write-Host '  ACTUALIZACIÓN DE APLICACIONES, DRIVERS Y WINDOWS' -ForegroundColor Cyan
Write-Host ('█' * 70) -ForegroundColor Cyan
Write-Host ("  Equipo:     {0}" -f $env:COMPUTERNAME)
Write-Host ("  PowerShell: {0}" -f $PSVersionTable.PSVersion)
Write-Host ("  Admin:      {0}" -f $(if (Test-IsAdmin) { 'Sí' } else { 'No' }))
Write-Host ("  Modo:       {0}" -f $(if ($DryRun) { 'DryRun (solo listar)' } elseif ($ScheduledRun) { 'Programado' } else { 'Manual' }))
Write-Host ("  Carpeta log: {0}" -f $LogFolder)
if ($script:DiagMode) { Write-Host '  Detalle:    activado (-Verbose o "Verbose": true en el JSON)' }
Write-DiagnosticContext

# Si PS < 7, relanzar o instalar automaticamente (salvo -NoRelaunch).
$needPwsh = ($PSVersionTable.PSVersion.Major -lt 7)
if ($needPwsh) {
    $relaunched = Ensure-PowerShell7 -NoRelaunch:$NoRelaunch
    if (-not $relaunched -and -not $NoRelaunch) {
        if (Install-PowerShell7) {
            # Relanzar ahora que está instalado
            Ensure-PowerShell7 | Out-Null
        } else {
            Write-WarnMsg "⚠️ Continuando en Windows PowerShell 5.1 (compatibilidad reducida)."
        }
    } elseif ($NoRelaunch) {
        Write-WarnMsg "-NoRelaunch solicitado: continuando en Windows PowerShell 5.1."
    }
}

# Aviso de privilegios
if (-not (Test-IsAdmin)) {
    Write-WarnMsg "ℹ️ Sugerencia: ejecuta como Administrador para mejores resultados (servicios, WU, instalación de PS7...)."
}

if ($DryRun) { Write-WarnMsg "ℹ️ Modo DryRun: solo se listan las actualizaciones pendientes." }
if (Get-PendingReboot) { Write-WarnMsg "⚠️ Ya hay un reinicio pendiente antes de empezar; algunas instalaciones podrían fallar." }

# Flujo de actualización
Configure-UpdaterScheduledTask
Invoke-LegacyTaskMigration
Update-RuckZuckApps
Update-WinGetApps
Update-MicrosoftStore
Update-VendorDrivers
Update-WindowsDriversAndUpdates

# Resumen final
Write-Host ''
Write-Host ('█' * 70) -ForegroundColor Cyan
Write-Host '  RESUMEN' -ForegroundColor Cyan
Write-Host ('█' * 70) -ForegroundColor Cyan
Write-Host ("  ✔ Correctos:      {0}" -f $script:Successes.Count) -ForegroundColor Green
$script:Successes | ForEach-Object { Write-Host "      • $_" -ForegroundColor Green }
if ($script:Skipped.Count -gt 0) {
    Write-Host ("  ➜ Omitidos:       {0}" -f $script:Skipped.Count) -ForegroundColor Cyan
    $script:Skipped | ForEach-Object { Write-Host "      • $_" -ForegroundColor Cyan }
}
Write-Host ("  ✖ Con problemas:  {0}" -f $script:Failures.Count) -ForegroundColor $(if ($script:Failures.Count -gt 0) { 'Yellow' } else { 'Green' })
$script:Failures | ForEach-Object { Write-Host "      • $_" -ForegroundColor Yellow }
Write-Host ("  Reinicio pendiente: {0}" -f $(if (Get-PendingReboot) { 'Sí' } else { 'No' }))
Write-Host ("  Log: {0}" -f $tsFile)
Write-Host ''
if ($script:Failures.Count -gt 0) { Write-WarnMsg "⚠️ Proceso finalizado con incidencias." } else { Write-Ok "✅ Proceso finalizado sin incidencias." }
try { Stop-Transcript | Out-Null } catch {}

if ($script:RebootScheduled) { & shutdown.exe /r /t 60 /c "Reinicio por actualizaciones pendientes" }
exit $(if ($script:Failures.Count -gt 0) { 1 } else { 0 })
