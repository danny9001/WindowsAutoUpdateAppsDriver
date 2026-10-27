# Ejecutar con pwsh -NoProfile -File tests/WinGetSystemInstall.Tests.ps1.
# Solo simula descargas, instaladores y comandos AppX; no instala nada.
$ErrorActionPreference='Stop'
$file=Join-Path (Split-Path $PSScriptRoot -Parent) 'UpdateAppsDrivers8.1.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
foreach($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Install-WinGet','Install-VCRedist','Install-WinGetWithClientModule','Find-ProvisionedWinGet')},$true)){ . ([scriptblock]::Create($definition.Extent.Text)) }
function Write-Info($msg) {}
function Write-Ok($msg) {}
function Write-Detail($msg) {}
function Write-Diag($msg) {}
function Write-WarnMsg($msg) { $script:Warnings.Add($msg) }
function Write-ErrMsg($msg) { $script:Errors.Add($msg) }
function Test-IsAdmin { $true }
function Test-Internet { param([switch]$VerboseMode) $true }
function Test-AppxDeploymentAvailable { $true }
function Test-AppSideloadingPolicy {}
function Test-DownloadSignature { param($Path,$Publisher) $true }
function Invoke-Download { param($Uri,$OutFile) Set-Content -LiteralPath $OutFile -Value 'x' }
function Start-Process { param($FilePath,$ArgumentList,[switch]$Wait,[switch]$PassThru) [pscustomobject]@{ExitCode=$script:VcExitCode} }
function Invoke-RestMethod { param($Uri,$Headers,$ErrorAction) [pscustomobject]@{ tag_name='v1.29.380'; assets=@(
    [pscustomobject]@{name='Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'; browser_download_url='https://example.invalid/b'},
    [pscustomobject]@{name='abc_License1.xml'; browser_download_url='https://example.invalid/l'},
    [pscustomobject]@{name='DesktopAppInstaller_Dependencies.zip'; browser_download_url='https://example.invalid/d'}) } }
function Expand-Archive { param($LiteralPath,$DestinationPath,$ErrorAction) $dir=Join-Path $DestinationPath 'x64'; New-Item -ItemType Directory -Path $dir -Force | Out-Null; Set-Content -LiteralPath (Join-Path $dir 'Microsoft.VCLibs.140.00_x64.appx') -Value 'x' }
function Invoke-WindowsPowerShellCommand { param($Command) $script:Commands.Add($Command); if($Command -like 'Add-AppxPackage*' -and $script:IsSystem){ throw 'Deployment failed with HRESULT: 0x80073CF9 (Local System)' }; if($Command -like 'Add-AppxPackage*' -and $script:UserAddFails){ throw 'Add-AppxPackage fallo' } }
function Test-WinGetInstalled { $script:Commands -match '^Add-AppxProvisionedPackage .*-LicensePath' }
function Test-IsSystemAccount { $script:IsSystem }
function Reset-State { $script:Commands=[Collections.Generic.List[string]]::new(); $script:Warnings=[Collections.Generic.List[string]]::new(); $script:Errors=[Collections.Generic.List[string]]::new() }
$env:TEMP=[IO.Path]::GetTempPath()

# VC++ 1638 (ya instalado) es correcto; otro codigo no.
Reset-State; $script:VcExitCode=1638
if(-not (Install-VCRedist)){throw 'VC++ 1638 se informo como fallo'}
$script:VcExitCode=1603
if(Install-VCRedist){throw 'VC++ 1603 se informo como correcto'}

# SYSTEM: sin Add-AppxPackage; se aprovisionan dependencias y bundle con licencia.
Reset-State; $script:VcExitCode=0; $script:IsSystem=$true; $script:UserAddFails=$false
if(-not (Install-WinGet)){throw "Instalacion como SYSTEM fallo: $($script:Warnings -join ' / ')"}
if($script:Commands -like 'Add-AppxPackage*'){throw 'Se intento Add-AppxPackage como SYSTEM'}
if(-not ($script:Commands -match '^Add-AppxProvisionedPackage .*VCLibs.*-SkipLicense')){throw 'No se aprovisiono la dependencia'}
if(-not ($script:Commands -match '^Add-AppxProvisionedPackage .*WinGet\.msixbundle.*-LicensePath')){throw 'No se aprovisiono el bundle'}

# Usuario administrador: si falla el registro por usuario, se aprovisiona igual.
Reset-State; $script:IsSystem=$false; $script:UserAddFails=$true
if(-not (Install-WinGet)){throw 'Un fallo de Add-AppxPackage corto la instalacion'}
if(-not ($script:Commands -match '^Add-AppxPackage .*WinGet\.msixbundle')){throw 'No se intento registrar para el usuario'}
if(-not ($script:Commands -match '^Add-AppxProvisionedPackage .*WinGet\.msixbundle.*-LicensePath')){throw 'No se aprovisiono tras el fallo por usuario'}

# Como SYSTEM se omite el respaldo Microsoft.WinGet.Client.
Reset-State; $script:IsSystem=$true
if(Install-WinGetWithClientModule){throw 'El respaldo de cliente no debe usarse como SYSTEM'}

# WinGet aprovisionado: se elige la version mas alta de la arquitectura del equipo.
$root=Join-Path ([IO.Path]::GetTempPath()) ('windowsapps-tests-'+[guid]::NewGuid().ToString('N'))
try {
    $arch=if ($env:PROCESSOR_ARCHITECTURE -match 'ARM64') { 'arm64' } elseif ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    foreach($v in @('1.9.100.0','1.29.380.0')){ $d=Join-Path $root "Microsoft.DesktopAppInstaller_${v}_${arch}__8wekyb3d8bbwe"; New-Item -ItemType Directory -Path $d -Force | Out-Null; Set-Content -LiteralPath (Join-Path $d 'winget.exe') -Value 'x' }
    New-Item -ItemType Directory -Path (Join-Path $root "Microsoft.DesktopAppInstaller_2.0.0.0_${arch}__8wekyb3d8bbwe") | Out-Null
    $found=Find-ProvisionedWinGet -Root $root
    if($found -notlike "*_1.29.380.0_${arch}__8wekyb3d8bbwe\winget.exe"){throw "WinGet aprovisionado incorrecto: $found"}
    if(Find-ProvisionedWinGet -Root (Join-Path $root 'no-existe')){throw 'Se encontro WinGet en una carpeta inexistente'}
} finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
'PASS: VC++ 1638, instalacion de WinGet como SYSTEM por aprovisionamiento, fallo por usuario no fatal, sin respaldo de cliente como SYSTEM y busqueda en WindowsApps.'
