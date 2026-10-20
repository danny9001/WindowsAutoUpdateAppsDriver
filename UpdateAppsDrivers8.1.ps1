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

.PARAMETER OutputFolder
  Carpeta para descargas y logs (por defecto, carpeta del script).

.NOTES
  - En Windows Server se omiten tareas de Microsoft Store.
  - Requiere privilegios de admin para partes de Windows Update e instalación de PS7.
#>

[CmdletBinding()]
param(
    [switch]$NoRelaunch,
    [switch]$SkipStore,
    [switch]$ForceWinGetReinstall,
    [switch]$ScheduledRun,
    [string]$OutputFolder = $(if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path })
)

# -------------------------
# Utilidades base y logging
# -------------------------
$script:UpdaterScriptPath = $PSCommandPath
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
        if ($SkipStore) { $argsToPass += '-SkipStore' }
        if ($ForceWinGetReinstall) { $argsToPass += '-ForceWinGetReinstall' }
        if ($ScheduledRun) { $argsToPass += '-ScheduledRun' }
        $argsToPass += @('-OutputFolder',"`"$OutputFolder`"")

        if ($PSCommandPath) {
            Start-Process -FilePath $pwshCmd -ArgumentList (@('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"") + $argsToPass) -Wait
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
    if ($ScheduledRun) { return $true }
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
        Write-Info "🔄 Actualizando/Restableciendo fuentes de WinGet..."
        Invoke-WinGet source update --disable-interactivity | Out-Null
        Invoke-WinGet source reset  --disable-interactivity | Out-Null  # restablece winget + msstore
    } catch {
        Write-WarnMsg "⚠️ No se pudieron preparar las fuentes de WinGet: $($_.Exception.Message)"
    }
}

function Get-WinGetUpgradesList {
    $text = Invoke-WinGet upgrade --accept-source-agreements --include-unknown --disable-interactivity | Out-String
    $lines = $text -split "`n" | Where-Object { $_ -match '^\S' }
    return $lines
}

# Extrae los Id de paquete de la salida de 'winget upgrade' (columnas separadas por 2+ espacios)
function Get-WinGetUpgradeIds {
    # Se parsea por POSICIÓN de columna (según la cabecera): cuando el nombre llena su columna
    # solo queda 1 espacio antes del Id y separar por 2+ espacios devolvía la versión como Id.
    $lines = Get-WinGetUpgradesList
    $idStart = -1; $verStart = -1
    $ids = foreach ($raw in $lines) {
        $line = $raw.TrimEnd()
        if ($line -match '^Name\s+Id\s+Version') {                      # cabecera (se repite en la 2ª tabla)
            $idStart  = $line.IndexOf('Id')
            $verStart = $line.IndexOf('Version')
            continue
        }
        if ($idStart -lt 0) { continue }
        if ($line -match '^-+$') { continue }                           # separador
        if ($line -match '\d+\s+upgrades?\s+available') { continue }    # resumen
        if ($line -match '^(No\s|The following)') { continue }
        if ($line.Length -le $idStart) { continue }
        $end = if ($verStart -gt $idStart -and $line.Length -ge $verStart) { $verStart - $idStart } else { $line.Length - $idStart }
        $line.Substring($idStart, $end).Trim()
    }
    return @($ids | Where-Object { $_ -match '^[\w\.\-]+$' } | Select-Object -Unique)
}

function Update-WinGetApps {
    Write-Info "=== Actualizando aplicaciones con WinGet... ==="
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
        if (-not $upgrades -or $upgrades.Count -eq 0) { Write-Ok "✅ No hay actualizaciones WinGet disponibles."; return }

        Write-WarnMsg "✨ Aplicaciones con actualización (WinGet):"
        $upgrades | ForEach-Object { Write-Host (" - " + $_) -ForegroundColor White }

        $ids = Get-WinGetUpgradeIds
        if (-not $ids -or $ids.Count -eq 0) {
            Write-WarnMsg "⚠️ No se pudieron extraer los Id de paquete; reintento con 'winget upgrade --all'..."
            Invoke-WinGet upgrade --all --include-unknown --include-pinned --accept-package-agreements --accept-source-agreements --silent --disable-interactivity
            Write-Ok "✅ Actualización WinGet completada."
            return
        }

        # Se actualiza paquete por paquete: si uno falla (p. ej. requiere --location),
        # 'winget upgrade --all' aborta todo el lote restante. Uno por uno, un fallo no bloquea al resto.
        foreach ($id in $ids) {
            Write-Info "🔄 Actualizando $id..."
            Invoke-WinGet upgrade --id $id --include-unknown --include-pinned --accept-package-agreements --accept-source-agreements --silent --disable-interactivity
            if ($LASTEXITCODE -eq 0) {
                Write-Ok "✅ $id actualizado."
            } elseif ($LASTEXITCODE -eq -1978335090) {
                Write-WarnMsg "⚠️ ${id}: tecnología de instalación distinta; se aplica desinstalar + reinstalar automáticamente."
                if ($id -eq 'Microsoft.Edge') {
                    # Edge no se desinstala: se fuerza su actualizador propio.
                    $eu = @("${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe","$env:ProgramFiles\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
                    if ($eu) {
                        Start-Process -FilePath $eu -ArgumentList '/ua /installsource scheduler' -Wait -NoNewWindow
                        Write-Ok "✅ Edge: se lanzó su actualizador integrado."
                    } else { Write-WarnMsg "⚠️ No se encontró MicrosoftEdgeUpdate.exe." }
                } else {
                    Invoke-WinGet uninstall --id $id --silent --disable-interactivity
                    if ($LASTEXITCODE -eq 0) {
                        Invoke-WinGet install --id $id --silent --accept-package-agreements --accept-source-agreements --disable-interactivity
                        if ($LASTEXITCODE -eq 0) { Write-Ok "✅ $id reinstalado en la versión nueva." }
                        else { Write-WarnMsg "⚠️ $id se desinstaló pero la reinstalación falló (código $LASTEXITCODE). Reinstálalo manualmente." }
                    } else {
                        Write-WarnMsg "⚠️ No se pudo desinstalar $id (código $LASTEXITCODE). Continúo."
                    }
                }
            } else {
                Write-WarnMsg "⚠️ $id no se pudo actualizar (código $LASTEXITCODE). Continúo con el resto."
            }
        }
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

        if (Test-WinGetInstalled) {
            Ensure-WinGetSources
            Write-Info "🔄 Actualizando apps Store vía WinGet (msstore)..."
            Invoke-WinGet upgrade --source msstore --all --include-unknown --accept-package-agreements --accept-source-agreements --silent --disable-interactivity
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

function Read-UpdaterYesNo {
    param([string]$Prompt)
    do { $answer = (Read-Host "$Prompt [S/N]").Trim() } while ($answer -notmatch '^(s|si|n|no)$')
    return ($answer -match '^(s|si)$')
}

function Configure-UpdaterScheduledTask {
    if ($ScheduledRun -or -not [Environment]::UserInteractive) { return }
    if (-not (Read-UpdaterYesNo 'Desea crear una tarea automatica semanal para este script?')) { return }
    if (-not (Test-IsAdmin)) {
        Write-WarnMsg 'Ejecute como Administrador para crear la tarea programada.'
        return
    }
    try {
        $scriptPath = $script:UpdaterScriptPath
        if (-not $scriptPath -or -not (Test-Path -LiteralPath $scriptPath)) { throw 'Se requiere ejecutar el script desde un archivo guardado.' }
        $pwshPath = Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'
        if (-not (Test-Path -LiteralPath $pwshPath)) {
            $command = Get-Command pwsh.exe -ErrorAction SilentlyContinue
            if (-not $command) { throw 'PowerShell 7 debe estar instalado antes de programar la tarea.' }
            $pwshPath = $command.Source
        }
        $hashAlgorithm = [Security.Cryptography.SHA256]::Create()
        try { $pathHash = [BitConverter]::ToString($hashAlgorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($scriptPath.ToLowerInvariant()))).Replace('-', '').Substring(0, 12) }
        finally { $hashAlgorithm.Dispose() }
        $taskName = "UpdateAppsDrivers8.1-$pathHash"
        $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existing -and -not (Read-UpdaterYesNo "La tarea $taskName ya existe. Desea reemplazar su horario?")) { return }

        Write-Info 'Dia semanal: 1=Lunes, 2=Martes, 3=Miercoles, 4=Jueves, 5=Viernes, 6=Sabado, 7=Domingo.'
        do { $day = (Read-Host 'Seleccione el dia (1-7)').Trim() } while ($day -notmatch '^[1-7]$')
        do { $time = (Read-Host 'Hora local del equipo en formato HH:mm (ejemplo 22:30)').Trim() } while ($time -notmatch '^([01][0-9]|2[0-3]):[0-5][0-9]$')
        $days = @('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')
        $dayNames = @('Lunes','Martes','Miercoles','Jueves','Viernes','Sabado','Domingo')
        $at = [datetime]::Today.Add([TimeSpan]::ParseExact($time, 'hh\:mm', [Globalization.CultureInfo]::InvariantCulture))
        Write-Info "La tarea se ejecutara como SYSTEM cada $($dayNames[[int]$day - 1]) a las $time, con instalacion automatica de WinGet si falta."
        $arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -ScheduledRun -OutputFolder "{1}"' -f $scriptPath, $OutputFolder.TrimEnd('\')
        if ($SkipStore) { $arguments += ' -SkipStore' }
        $action = New-ScheduledTaskAction -Execute $pwshPath -Argument $arguments -WorkingDirectory (Split-Path -Parent $scriptPath) -ErrorAction Stop
        $trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek $days[[int]$day - 1] -At $at -ErrorAction Stop
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest -ErrorAction Stop
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ErrorAction Stop
        $registration = @{ TaskName=$taskName; Action=$action; Trigger=$trigger; Principal=$principal; Settings=$settings; Description="Actualizaciones semanales de aplicaciones y drivers: $scriptPath"; ErrorAction='Stop' }
        if ($existing) { $registration.Force = $true }
        Register-ScheduledTask @registration | Out-Null
        Write-Ok "Tarea $taskName creada: $($dayNames[[int]$day - 1]) a las $time (horario local). Conserve el script en $scriptPath."
    } catch { Write-ErrMsg "No se pudo crear la tarea programada: $($_.Exception.Message)" }
}

# -------------------------
# MAIN
# -------------------------
Write-Info "Iniciando actualizaciones automáticas de aplicaciones y del sistema..."
Write-Host (" - PowerShell:  {0}" -f $PSVersionTable.PSVersion)
Write-Host (" - Admin:       {0}" -f $(if (Test-IsAdmin) { 'Sí' } else { 'No' }))
Write-Host (" - Carpeta log: {0}" -f $OutputFolder)

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

# Flujo de actualización
Configure-UpdaterScheduledTask
Update-RuckZuckApps
Update-WinGetApps
Update-MicrosoftStore
Update-WindowsDriversAndUpdates

Write-Ok "✅ Proceso finalizado."
try { Stop-Transcript | Out-Null } catch {}
