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

# -------------------------
# Utilidades base y logging
# -------------------------
$script:UpdaterScriptPath = $PSCommandPath
function Write-Info($msg)    { Write-Host $msg -ForegroundColor Cyan }
function Write-Ok($msg)      { Write-Host $msg -ForegroundColor Green }
function Write-WarnMsg($msg) { Write-Host $msg -ForegroundColor Yellow }
function Write-ErrMsg($msg)  { Write-Host $msg -ForegroundColor Red }
function Write-Detail($msg)  { Write-Host "    $msg" -ForegroundColor DarkGray }
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
        Schedule = [pscustomobject]@{ Enabled=$false; DayOfWeek='Sunday'; Time='22:00' }
        RuckZuck = [pscustomobject]@{ SkipShortNames=@(); DelayDays=0; ScanTimeoutSeconds=180; InstallTimeoutSeconds=1800; VersionCheckDays=7 }
    }
    if (Test-Path -LiteralPath $script:UpdaterConfigPath) {
        try {
            $data = Get-Content -LiteralPath $script:UpdaterConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ($null -eq $data -or $data -isnot [pscustomobject]) { throw 'Se requiere un objeto JSON.' }
            foreach ($name in @('AskQuestions','SkipStore','InstallWinGetIfMissing')) {
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

function Download-RZGet {
    param([string]$DestinationFolder = $OutputFolder)
    $dest = Join-Path $DestinationFolder 'RZGet.exe'
    if ($DryRun) {
        if (Test-Path -LiteralPath $dest) { return $dest }
        throw 'DryRun no descarga RZGet; copie el ejecutable antes de consultar.'
    }
    if ((Test-Path -LiteralPath $dest) -and ((Get-Item -LiteralPath $dest).LastWriteTime -gt (Get-Date).AddDays(-$script:UpdaterConfig.RuckZuck.VersionCheckDays))) { return $dest }
    Set-Tls12Enable; Set-ProxyDefaults
    $tmp = "$dest.$([guid]::NewGuid().ToString('N')).download"
    try {
        $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/rzander/ruckzuck/releases/latest' -Headers @{ 'User-Agent'='UpdateAppsDrivers8.1' } -ErrorAction Stop
        $asset = $release.assets | Where-Object { $_.name -eq 'RZGet.exe' } | Select-Object -First 1
        if (-not $asset -or $asset.digest -notmatch '^sha256:([a-fA-F0-9]{64})$') { throw 'La version publicada no incluye un SHA-256 verificable para RZGet.exe.' }
        $expectedHash = $Matches[1]
        if ((Test-Path -LiteralPath $dest) -and (Get-FileHash -LiteralPath $dest -Algorithm SHA256 -ErrorAction Stop).Hash -eq $expectedHash) {
            (Get-Item -LiteralPath $dest).LastWriteTime = Get-Date
            Write-Info "RZGet $($release.tag_name) ya esta actualizado."
            return $dest
        }
        Write-Info "📥 Descargando RZGet $($release.tag_name) y comprobando SHA-256..."
        $iwrParams = @{ Uri = $asset.browser_download_url; OutFile = $tmp; ErrorAction='Stop' }
        if ($PSVersionTable.PSVersion.Major -lt 7) { $iwrParams.UseBasicParsing = $true }
        Invoke-WebRequest @iwrParams
        if ((Get-FileHash -LiteralPath $tmp -Algorithm SHA256 -ErrorAction Stop).Hash -ne $expectedHash) { throw 'SHA-256 de RZGet no coincide con el publicado por GitHub.' }
        Test-DownloadSignature -Path $tmp -WarnOnly | Out-Null
        Move-Item -LiteralPath $tmp -Destination $dest -Force -ErrorAction Stop
        Write-Ok "✅ RZGet.exe descargado en: $dest"
    } catch {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
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
    $process = Start-Process -FilePath $Executable -ArgumentList $quotedArgs -PassThru -WindowStyle Hidden -RedirectStandardOutput $outPath -RedirectStandardError $errPath -ErrorAction Stop
    $finished = $process.WaitForExit($TimeoutSeconds * 1000)
    if (-not $finished) {
        try { Stop-Process -Id $process.Id -Force -ErrorAction Stop; $process.WaitForExit() } catch { Write-WarnMsg "No se pudo detener RZGet ($($process.Id)): $($_.Exception.Message)" }
    }
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
    Write-Section 1 4 'Aplicaciones (RuckZuck)'
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
                Write-Host ("    [{0}/{1}] {2} ... " -f $index, $pending.Count, $short) -NoNewline -ForegroundColor White
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
                        $script:Failures.Add("RuckZuck ${short}: codigo $code o instalacion no confirmada; log $($result.OutPath)")
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
    Invoke-WebRequest @params | Out-Null
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
    & $executable @Arguments
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
    Write-Section 2 4 'Aplicaciones (WinGet)'
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
            Write-Host ' ... ' -NoNewline
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
    Write-Section 3 4 'Microsoft Store'
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

function Update-WindowsDriversAndUpdates {
    Write-Section 4 4 'Windows Update (sistema y drivers)'
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

        if ($DryRun) {
            Write-Info "🔍 DryRun: actualizaciones de Windows pendientes (no se instalan)..."
            Get-WindowsUpdate -MicrosoftUpdate | Format-Table -AutoSize | Out-String | Write-Host
        } else {
            Write-Detail "Buscando e instalando actualizaciones..."
            $wuResult = $null
            try {
                $wuResult = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -IgnoreReboot -ErrorAction Stop
            } catch {
                # Solo si falla se reinician los servicios y se reintenta una vez.
                Write-WarnMsg "⚠️ Falló Windows Update ($($_.Exception.Message)); reinicio servicios y reintento una vez..."
                foreach ($s in @('wuauserv','cryptsvc')) {
                    try { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue; Start-Service -Name $s -ErrorAction Stop }
                    catch { Write-WarnMsg ("⚠️ No se pudo reiniciar {0}: {1}" -f $s, $_.Exception.Message) }
                }
                $wuResult = Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install -IgnoreReboot -ErrorAction Stop
            }
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
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations'
    )
    foreach ($k in $keys) { if (Test-Path $k) { return $true } }
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
        $scriptPath = $script:UpdaterScriptPath
        if (-not $scriptPath -or -not (Test-Path -LiteralPath $scriptPath)) { throw 'Se requiere ejecutar el script desde un archivo guardado.' }
        $hashAlgorithm = [Security.Cryptography.SHA256]::Create()
        try { $pathHash = [BitConverter]::ToString($hashAlgorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($scriptPath.ToLowerInvariant()))).Replace('-', '').Substring(0, 12) }
        finally { $hashAlgorithm.Dispose() }
        $taskName = "UpdateAppsDrivers8.1-$pathHash"
        $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if (-not $configuredSchedule -and $existing -and -not (Read-UpdaterYesNo "La tarea $taskName ya existe. Desea reemplazar su horario?")) { return }
        $pwshPath = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
        if (-not (Test-Path -LiteralPath $pwshPath)) {
            $command = Get-Command pwsh.exe -ErrorAction SilentlyContinue
            if (-not $command) { throw 'PowerShell 7 debe estar instalado antes de programar la tarea.' }
            $pwshPath = $command.Source
        }

        $days = @('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')
        $dayNames = @('Lunes','Martes','Miercoles','Jueves','Viernes','Sabado','Domingo')
        if ($configuredSchedule) {
            $day = [array]::IndexOf($days, [string]$script:UpdaterConfig.Schedule.DayOfWeek) + 1
            $time = $script:UpdaterConfig.Schedule.Time
        } else {
        Write-Info 'Dia semanal: 1=Lunes, 2=Martes, 3=Miercoles, 4=Jueves, 5=Viernes, 6=Sabado, 7=Domingo.'
        do { $day = (Read-Host 'Seleccione el dia (1-7)').Trim() } while ($day -notmatch '^[1-7]$')
        do { $time = (Read-Host 'Hora local del equipo en formato HH:mm (ejemplo 22:30)').Trim() } while ($time -notmatch '^([01][0-9]|2[0-3]):[0-5][0-9]$')
        }
        $at = [datetime]::Today.Add([TimeSpan]::ParseExact($time, 'hh\:mm', [Globalization.CultureInfo]::InvariantCulture))
        Write-Info "La tarea se ejecutara como SYSTEM cada $($dayNames[[int]$day - 1]) a las $time, con instalacion automatica de WinGet si falta."
        $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -ScheduledRun -OutputFolder "{1}"' -f $scriptPath, $OutputFolder.TrimEnd('\')
        # Leer SkipStore del JSON en cada ejecucion, sin fijarlo en los argumentos de la tarea.
        if ($IncludePinned) { $arguments += ' -IncludePinned' }
        if ($IncludeUnknown) { $arguments += ' -IncludeUnknown' }
        if ($AllowReinstall) { $arguments += ' -AllowReinstall' }
        if ($ExcludeIds.Count -gt 0) { $arguments += (' -ExcludeIds "{0}"' -f ($ExcludeIds -join ',')) }
        $arguments += " -RebootPolicy $RebootPolicy -LogRetentionDays $LogRetentionDays"
        $action = New-ScheduledTaskAction -Execute $pwshPath -Argument $arguments -WorkingDirectory (Split-Path -Parent $scriptPath) -ErrorAction Stop
        $trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek $days[[int]$day - 1] -At $at -ErrorAction Stop
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest -ErrorAction Stop
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable `
            -ExecutionTimeLimit (New-TimeSpan -Hours 4) -ErrorAction Stop
        $registration = @{ TaskName=$taskName; Action=$action; Trigger=$trigger; Principal=$principal; Settings=$settings; Description="Actualizaciones semanales de aplicaciones y drivers: $scriptPath"; ErrorAction='Stop' }
        if ($existing) { $registration.Force = $true }
        Register-ScheduledTask @registration | Out-Null
        $script:UpdaterConfig.SkipStore = [bool]$SkipStore
        if (-not $configuredSchedule) {
            $script:UpdaterConfig.Schedule.Enabled = $true
            $script:UpdaterConfig.Schedule.DayOfWeek = $days[[int]$day - 1]
            $script:UpdaterConfig.Schedule.Time = $time
            $script:UpdaterConfig.AskQuestions = $false
        }
        Save-UpdaterConfiguration
        Write-Ok "Tarea $taskName creada: $($dayNames[[int]$day - 1]) a las $time (horario local). Conserve el script en $scriptPath."
    } catch { Write-ErrMsg "No se pudo crear la tarea programada: $($_.Exception.Message)" }
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
Update-RuckZuckApps
Update-WinGetApps
Update-MicrosoftStore
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
