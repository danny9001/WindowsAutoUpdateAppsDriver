$ErrorActionPreference='Stop'
$file=Join-Path (Split-Path $PSScriptRoot -Parent) 'UpdateAppsDrivers8.1.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
$names=@('Update-VendorDrivers','Get-OemVendor','Compare-DriverVersion','Get-IntelSilentArguments','Find-IntelDriverUpdates','Install-IntelDriverUpdate','Update-IntelDrivers','Get-HPImageAssistantRecommendations','Update-HPDrivers','Update-DellDrivers','Update-LenovoDrivers','Update-OemDrivers','Get-PciDeviceName','Get-DriverWorkFolder')
foreach($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in $names},$true)){ . ([scriptblock]::Create($definition.Extent.Text)) }
function Write-Info($msg) {}
function Write-Diag($msg) {}
function Write-Ok($msg) {}
function Write-WarnMsg($msg) {}
function Write-ErrMsg($msg) {}
function Write-Detail($msg) {}

# Solo archivos temporales y comandos simulados; no se descarga ni instala ningun driver.
$root=Join-Path ([IO.Path]::GetTempPath()) ('vendor-driver-tests-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$OutputFolder=$root; $LogFolder=Join-Path $root 'Logs'; New-Item -ItemType Directory -Path $LogFolder | Out-Null
$DryRun=$false
$script:UpdaterConfig=[pscustomobject]@{Drivers=[pscustomobject]@{Sources=@('Oem','Intel','WindowsUpdate'); IncludeFirmware=$true; InstallVendorTool=$true; SkipIntelIds=@(); InstallTimeoutSeconds=60}}
function Reset-Lists { $script:Failures=[Collections.Generic.List[string]]::new(); $script:Successes=[Collections.Generic.List[string]]::new(); $script:Skipped=[Collections.Generic.List[string]]::new(); $script:DriverRebootRequired=$false }

try {
    # Cruce del catalogo de Intel con el inventario
    $os='windows-11-25h2-64'
    function New-Entry($id,$category,$version,$detection,$osList=@($os),$type='Default',$options='') {
        [pscustomobject]@{Id=$id; Name="Paquete $id"; Url="https://intel.example/$id"; InstallOptions=$options; AllowSilentInstallation=$false
            Files=@([pscustomobject]@{Url="https://downloadmirror.intel.com/$id/pkg$id.exe"; Hash='00'; OperatingSystems=$osList})
            Components=@([pscustomobject]@{Category=$category; Version=$version; DetectionType=$type; DetectionValues=@($detection)})}
    }
    $catalog=@(
        (New-Entry 1 'Wireless' '24.80.0.1' 'VEN_8086&DEV_7AF0'),
        (New-Entry 2 'Bluetooth' '24.70.0.4' 'VID_8087&PID_0033'),
        (New-Entry 3 'Graphics' '32.0.101.7000' 'VEN_8086&DEV_A7A1' -options '--nouninstall'),
        (New-Entry 4 'LAN' '30.0.0.1' 'VEN_8086&DEV_15F3'),
        (New-Entry 5 'Wireless' '99.0.0.0' 'VEN_8086&DEV_7AF0' -osList @('windows-10-22h2-64')),
        (New-Entry 6 'Graphics' '99.0.0.0' 'VEN_8086&DEV_A7A1' -type 'Guid')
    )
    $inventory=@(
        [pscustomobject]@{DeviceName='Wi-Fi'; HardwareId='PCI\VEN_8086&DEV_7AF0&SUBSYS_00948086'; DriverVersion='24.70.0.3'},
        [pscustomobject]@{DeviceName='Bluetooth'; HardwareId='USB\VID_8087&PID_0033&REV_0000'; DriverVersion='24.70.0.4'},
        [pscustomobject]@{DeviceName='UHD'; HardwareId='PCI\VEN_8086&DEV_A7A1&SUBSYS_8B78103C'; DriverVersion='32.0.101.7092'},
        [pscustomobject]@{DeviceName='Ethernet'; HardwareId='PCI\VEN_8086&DEV_15F3&SUBSYS_1'; DriverVersion='2.1.0.0'}
    )
    $updates=@(Find-IntelDriverUpdates -Catalog $catalog -Inventory $inventory -OsKey $os)
    if(($updates.Id -join ',') -ne '1,4'){throw "Cruce Intel incorrecto: $($updates.Id -join ',')"}
    if(($updates[0].Arguments -join ' ') -ne '/quiet /norestart' -or $null -ne $updates[1].Arguments){throw 'Opciones silenciosas incorrectas'}
    if((Get-IntelSilentArguments -Entry $catalog[2] -Category 'Graphics') -join ' ' -ne '-s --nouninstall'){throw 'Opciones de graficos incorrectas'}
    if(@(Find-IntelDriverUpdates -Catalog $catalog -Inventory $inventory -OsKey $os -SkipIds @('1')).Id -contains '1'){throw 'No se respeto SkipIntelIds'}
    if($null -ne (Compare-DriverVersion -Left 'abc' -Right '1.0')){throw 'Version no comparable aceptada'}

    # Instalacion Intel: hash, firma, verificacion de version y codigos
    $payload=[Text.Encoding]::ASCII.GetBytes('instalador simulado')
    $sha1=(Get-FileHash -InputStream ([IO.MemoryStream]::new($payload)) -Algorithm SHA1).Hash
    function Invoke-Download { param($Uri,$OutFile) [IO.File]::WriteAllBytes($OutFile,$script:Payload) }
    function Test-DownloadSignature { param($Path,$Publisher,[switch]$WarnOnly) return $script:SignatureOk }
    function Invoke-DriverProcess { param($FilePath,$Arguments,$TimeoutSeconds) $script:LastArguments=$Arguments; return [pscustomobject]@{TimedOut=$false; ExitCode=$script:ExitCode} }
    function Get-InstalledDriverInventory { return @([pscustomobject]@{DeviceName='Wi-Fi'; HardwareId=$updates[0].HardwareId; DriverVersion=$script:VersionAfter}) }
    $update=$updates[0]; $update.File.Hash=$sha1.ToLower()
    $script:Payload=$payload; $script:SignatureOk=$true; $script:ExitCode=0; $script:VersionAfter='24.80.0.1'
    if((Install-IntelDriverUpdate -Update $update).Status -ne 'Installed' -or ($script:LastArguments -join ' ') -ne '/quiet /norestart'){throw 'Instalacion confirmada no reconocida'}
    $script:VersionAfter='24.70.0.3'
    if((Install-IntelDriverUpdate -Update $update).Status -ne 'Failed'){throw 'Codigo 0 sin cambio de version marcado como exito'}
    $script:ExitCode=3010
    if((Install-IntelDriverUpdate -Update $update).Status -ne 'RebootRequired'){throw 'Codigo 3010 no reconocido'}
    $script:SignatureOk=$false; $failed=$false
    try { Install-IntelDriverUpdate -Update $update | Out-Null } catch { $failed=$true }
    if(-not $failed){throw 'Se instalo un paquete sin firma valida'}
    Get-ChildItem -LiteralPath (Join-Path $root 'Drivers\Intel') -File | Remove-Item -Force
    $script:SignatureOk=$true; $script:Payload=[Text.Encoding]::ASCII.GetBytes('alterado'); $failed=$false
    try { Install-IntelDriverUpdate -Update $update | Out-Null } catch { $failed=$true }
    if(-not $failed){throw 'Se acepto un paquete con SHA-1 distinto'}

    # Reporte de HP Image Assistant (formato del reporte XML real)
    $report=Join-Path $root 'hpia-report'; New-Item -ItemType Directory -Path $report | Out-Null
    Set-Content -LiteralPath (Join-Path $report 'equipo.xml') -Value '<HPIA><Recommendations><Drivers><Recommendation><TargetComponent>Intel DTT</TargetComponent><TargetVersion>9.0.1</TargetVersion><ReferenceVersion>9.0.2</ReferenceVersion><Solution><Softpaq><Id>sp1</Id><Name>Intel DTT</Name></Softpaq></Solution></Recommendation></Drivers><BIOS><Recommendation><TargetComponent>BIOS</TargetComponent><TargetVersion>01.13</TargetVersion><ReferenceVersion>01.14</ReferenceVersion><Solution><Softpaq><Id>sp2</Id><Name>BIOS</Name></Softpaq></Solution></Recommendation></BIOS></Recommendations></HPIA>'
    $recommendations=@(Get-HPImageAssistantRecommendations -ReportFolder $report)
    if(($recommendations.Category -join ',') -ne 'Drivers,BIOS' -or $recommendations[1].SoftPaq -ne 'sp2'){throw 'Reporte HPIA mal interpretado'}

    # HP: analisis, BitLocker solo con BIOS/firmware, codigos de salida
    function Get-HPImageAssistant { return 'hpia.exe' }
    function Suspend-BitLockerForFirmware { $script:BitLockerSuspended=$true }
    function Invoke-HPImageAssistant { param($Executable,$Categories,$Action) $script:HPCalls.Add("$Action|$($Categories -join ',')"); if($Action -eq 'List'){return [pscustomobject]@{TimedOut=$false; ExitCode=0; Report='r'; Recommendations=$script:HPRecs}}; return [pscustomobject]@{TimedOut=$false; ExitCode=$script:HPExit; Report='r'; Recommendations=@()} }
    Reset-Lists; $script:HPCalls=[Collections.Generic.List[string]]::new(); $script:BitLockerSuspended=$false; $script:HPRecs=$recommendations; $script:HPExit=3010
    Update-HPDrivers -Firmware $true
    if(($script:HPCalls -join ';') -ne 'List|Drivers,BIOS,Firmware;Install|Drivers,BIOS,Firmware' -or -not $script:BitLockerSuspended -or -not $script:DriverRebootRequired -or $script:Successes.Count -ne 1){throw 'Flujo HP con BIOS incorrecto'}
    Reset-Lists; $script:HPCalls.Clear(); $script:BitLockerSuspended=$false; $script:HPRecs=@($recommendations[0]); $script:HPExit=0
    Update-HPDrivers -Firmware $false
    if(($script:HPCalls -join ';') -ne 'List|Drivers;Install|Drivers' -or $script:BitLockerSuspended){throw 'BitLocker suspendido sin BIOS/firmware'}
    Reset-Lists; $script:HPCalls.Clear(); $script:HPExit=3020; $failed=$false
    try { Update-HPDrivers -Firmware $false } catch { $failed=$true }
    if(-not $failed){throw 'Codigo 3020 de HPIA no informado como fallo'}
    $DryRun=$true; Reset-Lists; $script:HPCalls.Clear()
    Update-HPDrivers -Firmware $true
    if(($script:HPCalls -join ';') -ne 'List|Drivers,BIOS,Firmware'){throw 'DryRun de HP instalo'}
    $DryRun=$false

    # Dell: argumentos y codigos de dcu-cli
    function Get-DellCommandUpdateCli { return 'dcu-cli.exe' }
    function Invoke-DriverProcess { param($FilePath,$Arguments,$TimeoutSeconds) $script:LastArguments=$Arguments; return [pscustomobject]@{TimedOut=$false; ExitCode=$script:ExitCode} }
    Reset-Lists; $script:ExitCode=1
    Update-DellDrivers -Firmware $true
    $joined=$script:LastArguments -join ' '
    if($joined -notmatch '^/applyUpdates -updateType=driver,bios,firmware -reboot=disable -autoSuspendBitLocker=enable' -or -not $script:DriverRebootRequired){throw "Argumentos Dell incorrectos: $joined"}
    Reset-Lists; $script:ExitCode=500
    Update-DellDrivers -Firmware $false
    if(($script:LastArguments -join ' ') -notmatch '-updateType=driver ' -or $script:Failures.Count -or $script:Successes.Count){throw 'Codigo 500 de Dell mal interpretado'}
    $script:ExitCode=2; $failed=$false
    try { Update-DellDrivers -Firmware $false } catch { $failed=$true }
    if(-not $failed){throw 'Codigo de error de Dell no informado'}
    $DryRun=$true; $script:ExitCode=0
    Update-DellDrivers -Firmware $true
    if($script:LastArguments[0] -ne '/scan'){throw 'DryRun de Dell instalo'}
    $DryRun=$false

    # Lenovo: filtrado por tipo, BitLocker y resultados
    function Get-Module { param($Name,[switch]$ListAvailable) return [pscustomobject]@{Name='LSUClient'} }
    function Import-Module { param($Name) }
    function Get-LSUpdate { return @(
        [pscustomobject]@{Type='Driver'; Title='Audio'; Version='1'; Installer=[pscustomobject]@{Unattended=$true}},
        [pscustomobject]@{Type='BIOS'; Title='BIOS'; Version='2'; Installer=[pscustomobject]@{Unattended=$true}},
        [pscustomobject]@{Type='Application'; Title='Vantage'; Version='3'; Installer=[pscustomobject]@{Unattended=$true}},
        [pscustomobject]@{Type='Driver'; Title='Manual'; Version='4'; Installer=[pscustomobject]@{Unattended=$false}}) }
    function Install-LSUpdate { param([Parameter(ValueFromPipeline=$true)]$Package) process { $script:LenovoInstalled.Add($Package.Title); [pscustomobject]@{Title=$Package.Title; Success=$true; PendingAction=$(if($Package.Type -eq 'BIOS'){'REBOOT_MANDATORY'}else{'NONE'})} } }
    Reset-Lists; $script:LenovoInstalled=[Collections.Generic.List[string]]::new(); $script:BitLockerSuspended=$false
    Update-LenovoDrivers -Firmware $true
    if(($script:LenovoInstalled -join ',') -ne 'Audio,BIOS' -or -not $script:BitLockerSuspended -or -not $script:DriverRebootRequired){throw 'Flujo Lenovo incorrecto'}
    Reset-Lists; $script:LenovoInstalled.Clear(); $script:BitLockerSuspended=$false
    Update-LenovoDrivers -Firmware $false
    if(($script:LenovoInstalled -join ',') -ne 'Audio' -or $script:BitLockerSuspended){throw 'Lenovo incluyo BIOS sin IncludeFirmware'}

    # Fabricante: sin corriente alterna se omite el firmware
    function Get-OemVendor { return 'Dell' }
    function Test-OnAcPower { return $false }
    function Update-DellDrivers { param([bool]$Firmware) $script:FirmwareRequested=$Firmware }
    Reset-Lists
    Update-OemDrivers
    if($script:FirmwareRequested -or $script:Skipped.Count -ne 1){throw 'Se pidio firmware con bateria'}

    # Fabricante: HPE (servidores) no es HP
    Remove-Item Function:\Get-OemVendor
    foreach($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-OemVendor'},$true)){ . ([scriptblock]::Create($definition.Extent.Text)) }
    function Get-CimInstance { param($ClassName,$ErrorAction) return [pscustomobject]@{Manufacturer=$script:Manufacturer} }
    $expected=@{'HP'='HP'; 'Hewlett-Packard'='HP'; 'HPE'=$null; 'Dell Inc.'='Dell'; 'LENOVO'='Lenovo'; 'Microsoft Corporation'=$null}
    foreach($pair in $expected.GetEnumerator()){ $script:Manufacturer=$pair.Key; if((Get-OemVendor) -ne $pair.Value){throw "Fabricante $($pair.Key) mal clasificado"} }
    Remove-Item Function:\Get-CimInstance

    # Windows Server: no se ejecutan herramientas de cliente ni el catalogo de Intel
    function Write-Section { param($Number,$Total,$Title) }
    function Test-IsAdmin { return $true }
    function Test-Internet { param([switch]$VerboseMode) return $true }
    function Update-OemDrivers { $script:VendorCalls.Add('Oem') }
    function Update-IntelDrivers { $script:VendorCalls.Add('Intel') }
    function Write-DevicesWithoutDriver { $script:VendorCalls.Add('Missing') }
    $script:VendorCalls=[Collections.Generic.List[string]]::new()
    function Get-IsServer { return $true }
    Update-VendorDrivers
    if($script:VendorCalls.Count){throw 'Se ejecutaron herramientas de cliente en Windows Server'}
    function Get-IsServer { return $false }
    Update-VendorDrivers
    if(($script:VendorCalls -join ',') -ne 'Oem,Intel,Missing'){throw "Flujo de equipo cliente incorrecto: $($script:VendorCalls -join ',')"}

    # pci.ids: nombre de un dispositivo sin driver
    $script:PciIds=@('# comentario','8086  Intel Corporation','	7af0  Alder Lake-S PCH CNVi WiFi','	a7a1  Raptor Lake-P [Iris Xe Graphics]','8087  Intel Corp.')
    if((Get-PciDeviceName -HardwareId 'PCI\VEN_8086&DEV_A7A1&SUBSYS_1') -ne 'Intel Corporation Raptor Lake-P [Iris Xe Graphics]'){throw 'pci.ids mal interpretado'}
    if((Get-PciDeviceName -HardwareId 'PCI\VEN_8086&DEV_FFFF') -ne 'Intel Corporation'){throw 'Fabricante pci.ids sin dispositivo incorrecto'}
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
'PASS: cruce Intel (version, SO, omisiones, opciones), instalacion con hash/firma/verificacion, HPIA, Dell, Lenovo, firmware con bateria y pci.ids.'
