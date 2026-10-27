$ErrorActionPreference='Stop'
$file=Join-Path (Split-Path $PSScriptRoot -Parent) 'UpdateAppsDrivers8.1.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
foreach($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Get-LegacyUpdaterTasks','Get-LegacyTaskSchedule','Invoke-LegacyTaskMigration')},$true)){ . ([scriptblock]::Create($definition.Extent.Text)) }
function Write-Info($msg) {}
function Write-Diag($msg) {}
function Write-Ok($msg) {}
function Write-WarnMsg($msg) {}
function Write-ErrMsg($msg) {}
function Test-IsAdmin { return $true }
function Save-UpdaterConfiguration { $script:Saved=$true }
function Get-UpdaterTaskName { return 'UpdateAppsDrivers8.1-abc' }

# Solo tareas simuladas; no se consulta ni modifica el Programador de tareas real.
function New-Task($name,$arguments,$trigger) { [pscustomobject]@{TaskName=$name; TaskPath='\'; Actions=@([pscustomobject]@{Execute='PowerShell.exe'; Arguments=$arguments}); Triggers=@($trigger)} }
$weeklyFriday=[pscustomobject]@{StartBoundary='2026-01-02T03:15:00'; DaysOfWeek=32}
$daily=[pscustomobject]@{StartBoundary='2026-01-01T21:45:00'}
$twoDays=[pscustomobject]@{StartBoundary='2026-01-01T08:00:00'; DaysOfWeek=3}
$allTasks=@(
    (New-Task 'Manual72' '-File "C:\Scripts\UpdateAppsDrivers7.2.ps1"' $weeklyFriday),
    (New-Task 'DailyUpdateAppsDrivers' '-File "C:\Scripts\UpdateAppsDrivers3.ps1"' $daily),
    (New-Task 'UpdateAppsDrivers8.1-otra' '-File "D:\Otra\UpdateAppsDrivers8.1.ps1" -ScheduledRun' $weeklyFriday),
    (New-Task 'Ajena' '-File "C:\Scripts\Backup.ps1"' $daily)
)
function Get-ScheduledTask { param($TaskName,$ErrorAction) if($TaskName){ if($script:CurrentExists){ return [pscustomobject]@{TaskName=$TaskName} }; return $null }; return $allTasks }
function Register-UpdaterScheduledTask { param($DayOfWeek,$Time,[switch]$Replace) if($script:RegisterFails){throw 'acceso denegado'}; $script:RegisteredSchedule="$DayOfWeek $Time"; $script:CurrentExists=$script:VerifyAfterCreate; return 'UpdateAppsDrivers8.1-abc' }
function Unregister-ScheduledTask { param($TaskName,$TaskPath,[switch]$Confirm,$ErrorAction) $script:Removed.Add($TaskName) }
function Reset-State {
    $script:Failures=[Collections.Generic.List[string]]::new(); $script:Successes=[Collections.Generic.List[string]]::new()
    $script:Removed=[Collections.Generic.List[string]]::new(); $script:RegisteredSchedule=$null; $script:Saved=$false
    $script:CurrentExists=$false; $script:RegisterFails=$false; $script:VerifyAfterCreate=$true
}
$DryRun=$false
$script:UpdaterConfig=[pscustomobject]@{Schedule=[pscustomobject]@{Enabled=$false; DayOfWeek='Sunday'; Time='22:00'}}

$legacy=@(Get-LegacyUpdaterTasks)
if(($legacy.TaskName -join ',') -ne 'Manual72,DailyUpdateAppsDrivers'){throw "Deteccion incorrecta: $($legacy.TaskName -join ',')"}
$s=Get-LegacyTaskSchedule -Task $legacy[0]; if("$($s.DayOfWeek) $($s.Time)" -ne 'Friday 03:15'){throw "Horario semanal incorrecto: $($s.DayOfWeek) $($s.Time)"}
$s=Get-LegacyTaskSchedule -Task $legacy[1]; if("$($s.DayOfWeek) $($s.Time)" -ne 'Sunday 21:45'){throw "Horario diario incorrecto: $($s.DayOfWeek) $($s.Time)"}
$s=Get-LegacyTaskSchedule -Task (New-Task 'x' 'UpdateAppsDrivers8.ps1' $twoDays); if("$($s.DayOfWeek) $($s.Time)" -ne 'Sunday 08:00'){throw 'Horario de varios dias incorrecto'}

Reset-State
Invoke-LegacyTaskMigration
if($script:RegisteredSchedule -ne 'Friday 03:15' -or -not $script:Saved -or ($script:Removed -join ',') -ne 'Manual72,DailyUpdateAppsDrivers' -or $script:Successes.Count -ne 2){throw 'Migracion sin tarea 8.1 incorrecta'}

Reset-State; $script:CurrentExists=$true
Invoke-LegacyTaskMigration
if($script:RegisteredSchedule -or $script:Removed.Count -ne 2){throw 'Con tarea 8.1 existente no se debe crear otra'}

Reset-State; $script:RegisterFails=$true
Invoke-LegacyTaskMigration
if($script:Removed.Count -or $script:Failures.Count -ne 1){throw 'Se elimino la tarea antigua aunque fallo la nueva'}

Reset-State; $script:VerifyAfterCreate=$false
Invoke-LegacyTaskMigration
if($script:Removed.Count -or $script:Failures.Count -ne 1){throw 'Se elimino la tarea antigua sin verificar la nueva'}

Reset-State; $DryRun=$true
Invoke-LegacyTaskMigration
if($script:RegisteredSchedule -or $script:Removed.Count){throw 'DryRun modifico tareas'}
'PASS: deteccion por nombre y accion, otras copias 8.1 intactas, horario semanal/diario, tarea 8.1 existente, fallo y verificacion antes de eliminar, DryRun.'
