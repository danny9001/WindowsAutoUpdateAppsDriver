$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'Deploy-UpdateAppsDriversRemote.ps1')
if((ConvertTo-UpdaterDate '2026-12-25 22:30').Hour -ne 22){throw 'Fecha invalida'}
foreach($invalid in @('2026-02-30 22:30','25/12/2026 22:30','2026-12-25 25:00')) {
    $caught=$false; try { ConvertTo-UpdaterDate $invalid | Out-Null } catch { $caught=$true }; if(-not $caught){throw "Se acepto fecha invalida: $invalid"}
}
$targets=@(Get-UpdaterTargets -Names @('PC01,SRV01','PC01') -ListPath '')
if(($targets -join ',') -ne 'PC01,SRV01'){throw 'Lista de destinos incorrecta'}
$caught=$false; try { Get-UpdaterTargets -Names @('pc01;bad/name') -ListPath '' | Out-Null } catch {$caught=$true}; if(-not $caught){throw 'Se acepto un nombre invalido'}

# Las sesiones, el Programador de tareas y el destino se simulan en una carpeta temporal.
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('remote-updater-tests-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$source=Join-Path $root 'UpdateAppsDrivers8.1.ps1'
$hash=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
$credential=[pscredential]::new('example\admin',(ConvertTo-SecureString 'not-a-real-password' -AsPlainText -Force))
$script:FakeTasks=@{}; $script:Registrations=0
function New-PSSession {param($ComputerName,$Credential,$Authentication,$ErrorAction) if($ComputerName -eq 'unreachable'){throw 'WinRM no disponible'}; return [pscustomobject]@{Name=$ComputerName} }
function Remove-PSSession {param($Session,$ErrorAction)}
function Invoke-Command {param($Session,$ErrorAction,$ArgumentList,$ScriptBlock) & $ScriptBlock @ArgumentList }
function Copy-Item {param($LiteralPath,$Destination,$ToSession,[switch]$Force,$ErrorAction) Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination -Force:$Force -ErrorAction Stop }
function Get-ScheduledTask {param($TaskName,$ErrorAction) if($script:FakeTasks.ContainsKey($TaskName)){return $script:FakeTasks[$TaskName]} }
function New-ScheduledTaskAction {param($Execute,$Argument,$WorkingDirectory,$ErrorAction) [pscustomobject]@{Execute=$Execute; Argument=$Argument; WorkingDirectory=$WorkingDirectory} }
function New-ScheduledTaskTrigger {param([switch]$Once,$At,$ErrorAction) [pscustomobject]@{Once=$Once;At=$At} }
function New-ScheduledTaskPrincipal {param($UserId,$LogonType,$RunLevel,$ErrorAction) [pscustomobject]@{UserId=$UserId;RunLevel=$RunLevel} }
function New-ScheduledTaskSettingsSet {param($MultipleInstances,[switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries,$ExecutionTimeLimit,$ErrorAction) [pscustomobject]@{MultipleInstances=$MultipleInstances} }
function Register-ScheduledTask {param($TaskName,$Action,$Trigger,$Principal,$Settings,$Description,$ErrorAction) $script:FakeTasks[$TaskName]=[pscustomobject]@{Action=$Action;Actions=@([pscustomobject]@{Arguments=$Action.Argument});Description=$Description;State='Ready';Trigger=$Trigger;Principal=$Principal;Settings=$Settings}; $script:Registrations++ }
$date=(Get-Date).AddDays(2)
$date=[datetime]::ParseExact($date.ToString('yyyy-MM-dd HH:mm'),'yyyy-MM-dd HH:mm',[Globalization.CultureInfo]::InvariantCulture)
$result=Invoke-UpdaterDeployment -Target 'PC01' -Date $date -DomainCredential $credential -LocalScript $source -DestinationFolder $testRoot -ExpectedHash $hash
if($result.Estado -ne 'Programado'){throw "Fallo de despliegue simulado: $($result.Detalle)"}
$task=$script:FakeTasks[$result.Tarea]
if(-not $task.Trigger.Once -or $task.Trigger.At -ne $date -or $task.Principal.UserId -ne 'SYSTEM'){throw 'Tarea puntual o principal incorrecto'}
if($task.Action.Argument -notmatch '-ScheduledRun.*-SkipLegacyTaskMigration'){throw 'No se evita la migracion de tareas anteriores'}
if((Get-FileHash -LiteralPath $result.Script -Algorithm SHA256).Hash -ne $hash){throw 'Copia remota incorrecta'}
$config=Get-Content -LiteralPath (Join-Path $testRoot 'UpdateAppsDrivers8.1.config.json') -Raw | ConvertFrom-Json
if($config.AskQuestions -or $config.Schedule.Enabled -or $config.Drivers.IncludeFirmware){throw 'Configuracion desatendida insegura'}
$again=Invoke-UpdaterDeployment -Target 'PC01' -Date $date -DomainCredential $credential -LocalScript $source -DestinationFolder $testRoot -ExpectedHash $hash
if($again.Estado -ne 'Actualizado' -or -not (Test-Path -LiteralPath $again.Respaldo) -or $script:Registrations -ne 1){throw "Despliegue repetido: no actualizo el script o registro otra tarea: $($again.Detalle)"}
if((Get-FileHash -LiteralPath $again.Script -Algorithm SHA256).Hash -ne $hash){throw 'Despliegue repetido: copia incorrecta'}
$script:FakeTasks[$result.Tarea].State='Running'
$running=Invoke-UpdaterDeployment -Target 'PC01' -Date $date -DomainCredential $credential -LocalScript $source -DestinationFolder $testRoot -ExpectedHash $hash
if($running.Estado -ne 'Error' -or $running.Detalle -notmatch 'ejecutando'){throw 'Se actualizo durante una ejecucion'}
$script:FakeTasks[$result.Tarea].State='Ready'; $script:FakeTasks[$result.Tarea].Description='Otra tarea'
$foreign=Invoke-UpdaterDeployment -Target 'PC01' -Date $date -DomainCredential $credential -LocalScript $source -DestinationFolder $testRoot -ExpectedHash $hash
if($foreign.Estado -ne 'Error' -or $foreign.Detalle -notmatch 'no es de este despliegue'){throw 'Se acepto una tarea ajena'}
$config.SkipPackages=@('Example.App')
$config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $testRoot 'UpdateAppsDrivers8.1.config.json') -Encoding UTF8
$later=Invoke-UpdaterDeployment -Target 'PC01' -Date $date.AddMinutes(2) -DomainCredential $credential -LocalScript $source -DestinationFolder $testRoot -ExpectedHash $hash
if($later.Estado -ne 'Programado' -or -not (Test-Path -LiteralPath $later.Respaldo)){throw 'No se respaldo el script anterior'}
$after=Get-Content -LiteralPath (Join-Path $testRoot 'UpdateAppsDrivers8.1.config.json') -Raw | ConvertFrom-Json
if($after.SkipPackages[0] -ne 'Example.App'){throw 'Se sobrescribio la configuracion existente'}
$offline=Invoke-UpdaterDeployment -Target 'unreachable' -Date $date -DomainCredential $credential -LocalScript $source -DestinationFolder $testRoot -ExpectedHash $hash
if($offline.Estado -ne 'Error'){throw 'No se reporto el equipo inaccesible'}
$badHash=Invoke-UpdaterDeployment -Target 'PC02' -Date $date.AddMinutes(1) -DomainCredential $credential -LocalScript $source -DestinationFolder $testRoot -ExpectedHash ('0'*64)
if($badHash.Estado -ne 'Error' -or $badHash.Detalle -notmatch 'SHA-256'){throw 'No se rechazo hash incorrecto'}
'PASS: fechas, validacion, copia, hash, tarea unica SYSTEM, actualizacion con tarea propia existente, proteccion de tareas ajenas o en ejecucion y error WinRM; sin conexiones reales.'
