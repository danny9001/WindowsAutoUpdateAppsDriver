$ErrorActionPreference = 'Stop'
$file=Join-Path (Split-Path $PSScriptRoot -Parent) 'UpdateAppsDrivers8.1.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
$definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Resolve-WinGetFailure'},$true)
. ([scriptblock]::Create($definition.Extent.Text))
function Write-Info($msg) {}
$script:Failures=[Collections.Generic.List[string]]::new(); $script:Successes=[Collections.Generic.List[string]]::new()
function Write-Ok($msg) {}
function Write-WarnMsg($msg) {}
function Save-UpdaterConfiguration {}
function Write-Host { param($Object,$ForegroundColor) $script:Messages.Add([string]$Object) }
function Add-Content { param([Parameter(ValueFromPipeline=$true)]$Value,$LiteralPath,$Encoding) process { $script:Records.Add([string]$Value) } }
function Read-Host { param($Prompt) if($script:Answers.Count -eq 0){throw 'Pregunta inesperada'}; $script:Answers.Dequeue() }
function Invoke-WinGet { $script:Calls.Add(($args -join ' ')); if($script:ThrowRetry){throw 'Fallo simulado'}; $global:LASTEXITCODE=$script:RetryCode }
function Reset-RecoveryTest([string[]]$Answers) {
    $script:Answers=[Collections.Generic.Queue[string]]::new()
    foreach($answer in $Answers){$script:Answers.Enqueue($answer)}
    $script:Calls=[Collections.Generic.List[string]]::new()
    $script:Records=[Collections.Generic.List[string]]::new()
    $script:Messages=[Collections.Generic.List[string]]::new()
    $script:RetryCode=0; $script:ThrowRetry=$false
}
$OutputFolder='C:\Medios'; $LogFolder='C:\Medios'; $tsFile='C:\Medios\Actualizar-test.log'; $ScheduledRun=$false
$script:UpdaterConfig=[pscustomobject]@{AskQuestions=$true; SkipPackages=@()}
Reset-RecoveryTest @('4','2')
Resolve-WinGetFailure -Id 'Microsoft.SQLServer.OLEDBDriver' -Details '1603; Installer log: C:\Logs\ole.log'
if($script:Calls.Count -ne 0 -or ($script:Messages -join ' ') -notmatch 'winget upgrade.*--exact --interactive'){throw 'Opcion 2 incorrecta'}
if(($script:Records -join ' ') -notmatch 'C:\\Logs\\ole.log'){throw 'No se guardo la ruta del log'}
Reset-RecoveryTest @('3')
Resolve-WinGetFailure -Id 'Test.App' -Details 'fallo'
if($script:Calls.Count){throw 'Omitir ejecuto WinGet'}
if ('Test.App' -notin $script:UpdaterConfig.SkipPackages) { throw 'No se guardo el paquete omitido' }
Reset-RecoveryTest @('1')
Resolve-WinGetFailure -Id 'Test.App' -Details 'fallo'
if($script:Calls.Count -ne 1 -or $script:Calls[0] -notmatch '^upgrade --id Test.App --exact --interactive'){throw 'Reintento incorrecto'}
Reset-RecoveryTest @('1'); $script:RetryCode=1603
Resolve-WinGetFailure -Id 'Test.App' -Details 'fallo' -Operation install
if($script:Calls[0] -notmatch '^install ' -or ($script:Records -join ' ') -notmatch '1603'){throw 'Fallo del reintento no registrado'}
Reset-RecoveryTest @('1'); $script:ThrowRetry=$true
Resolve-WinGetFailure -Id 'Test.App' -Details 'fallo'
$ScheduledRun=$true
Reset-RecoveryTest @()
Resolve-WinGetFailure -Id 'Test.App' -Details 'fallo automatico'
if($script:Calls.Count -or -not $script:Records.Count){throw 'Modo programado incorrecto'}
$ScheduledRun=$false; $script:UpdaterConfig.AskQuestions=$false
Reset-RecoveryTest @()
Resolve-WinGetFailure -Id 'Test.App' -Details 'fallo sin preguntas'
if($script:Calls.Count -or -not $script:Records.Count){throw 'AskQuestions=false incorrecto'}
'PASS: mostrar comando, omitir, reintento visible, fallo y excepcion, registro de log y ScheduledRun sin preguntas.'

