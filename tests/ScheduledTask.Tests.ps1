# Ejecutar con pwsh -NoProfile -File tests/ScheduledTask.Tests.ps1.
# Solo extrae funciones y simula cmdlets; no ejecuta actualizaciones ni registra tareas reales.
$ErrorActionPreference = 'Stop'
$file = Join-Path (Split-Path $PSScriptRoot -Parent) 'UpdateAppsDrivers8.1.ps1'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Read-UpdaterYesNo','Configure-UpdaterScheduledTask','Confirm-WinGetInstallation')}, $true)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
function Write-Info($msg) {}
function Write-Ok($msg) {}
function Write-WarnMsg($msg) {}
function Write-ErrMsg($msg) { throw $msg }
function Test-IsAdmin { return $true }
function Test-Path { param($LiteralPath) return $true }
function Get-ScheduledTask { param($TaskName, $ErrorAction) return $script:Existing }
function New-ScheduledTaskAction { param($Execute, $Argument, $WorkingDirectory, $ErrorAction) return @{Execute=$Execute; Arguments=$Argument; WorkingDirectory=$WorkingDirectory} }
function New-ScheduledTaskTrigger { param([switch]$Weekly, $WeeksInterval, $DaysOfWeek, $At, $ErrorAction) return @{Day=$DaysOfWeek; At=$At} }
function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel, $ErrorAction) return @{User=$UserId; Level=$RunLevel} }
function New-ScheduledTaskSettingsSet { param([switch]$StartWhenAvailable, $MultipleInstances, $ErrorAction) return @{Instances=$MultipleInstances} }
function Register-ScheduledTask { param($TaskName,$Action,$Trigger,$Principal,$Settings,$Description,[switch]$Force,$ErrorAction) $script:Registered=@{Action=$Action; Trigger=$Trigger; Principal=$Principal; Settings=$Settings; Force=$Force} }
function Read-Host { param($Prompt) if ($script:Answers.Count -eq 0) { throw 'Pregunta inesperada' }; return $script:Answers.Dequeue() }
function Set-Answers([string[]]$Values) { $script:Answers = [Collections.Generic.Queue[string]]::new(); foreach ($value in $Values) { $script:Answers.Enqueue($value) } }
$ScheduledRun=$false; $SkipStore=$true; $OutputFolder='C:\Medios'; $script:Existing=$null; $script:Registered=$null
$script:UpdaterScriptPath = $file
Set-Answers @('N')
Configure-UpdaterScheduledTask
if ($script:Registered) { throw 'Se creo una tarea al responder N' }
Set-Answers @('S','9','1','25:00','22:30')
Configure-UpdaterScheduledTask
if (-not $script:Registered) { throw 'No se registro la tarea' }
if ($script:Registered.Trigger.Day -ne 'Monday' -or $script:Registered.Trigger.At.Hour -ne 22 -or $script:Registered.Trigger.At.Minute -ne 30) { throw 'Dia u hora incorrectos' }
if ($script:Registered.Principal.User -ne 'SYSTEM' -or $script:Registered.Settings.Instances -ne 'IgnoreNew') { throw 'Principal o concurrencia incorrectos' }
if ($script:Registered.Action.Arguments -notmatch '-NonInteractive.*-ScheduledRun' -or $script:Registered.Action.Arguments -notmatch '-SkipStore') { throw 'Faltan opciones desatendidas' }
$script:Existing=@{Name='existing'}; $script:Registered=$null
Set-Answers @('S','N')
Configure-UpdaterScheduledTask
if ($script:Registered) { throw 'Se reemplazo una tarea sin confirmar' }
$ScheduledRun=$true
Set-Answers @()
Configure-UpdaterScheduledTask
if (-not (Confirm-WinGetInstallation)) { throw 'La ejecucion programada no permite bootstrap WinGet' }
Write-Output 'PASS: sintaxis, rechazo, validacion de dia/hora, accion SYSTEM, reemplazo protegido y ejecucion sin preguntas.'
