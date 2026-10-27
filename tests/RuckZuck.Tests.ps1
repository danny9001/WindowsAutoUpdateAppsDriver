$ErrorActionPreference='Stop'
$file=Join-Path (Split-Path $PSScriptRoot -Parent) 'UpdateAppsDrivers8.1.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
foreach($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Update-RuckZuckApps','Get-RuckZuckPending','Invoke-RuckZuckProcess')},$true)){ . ([scriptblock]::Create($definition.Extent.Text)) }
function Write-Info($msg) {}
function Write-Ok($msg) {}
function Write-WarnMsg($msg) {}
function Write-ErrMsg($msg) {}
function Write-Detail($msg) {}
function Write-Section {param($Number,$Total,$Title)}
$LogFolder=Join-Path ([IO.Path]::GetTempPath()) ('rz-tests-'+[guid]::NewGuid().ToString('N'))
$script:UpdaterConfig=[pscustomobject]@{RuckZuck=[pscustomobject]@{SkipShortNames=@('SkipMe'); DelayDays=5; ScanTimeoutSeconds=180; InstallTimeoutSeconds=30}}
$ScheduledRun=$true; $DryRun=$false

# Ejecutar solo procesos de prueba; nunca se inicia el actualizador real.
$exe=(Get-Command pwsh.exe -ErrorAction Stop).Source
$processResult=Invoke-RuckZuckProcess -Executable $exe -Arguments @('-NoProfile','-Command','Write-Output test-ok') -TimeoutSeconds 15 -LogLabel 'probe'
if($processResult.TimedOut -or $processResult.ExitCode -ne 0 -or $processResult.Stdout -notcontains 'test-ok'){throw 'Captura de proceso fallida'}
$processResult=Invoke-RuckZuckProcess -Executable $exe -Arguments @('-NoProfile','-Command','Start-Sleep -Seconds 5') -TimeoutSeconds 1 -LogLabel 'timeout'
if(-not $processResult.TimedOut){throw 'No se limito el tiempo del proceso'}

function Invoke-RuckZuckProcess {
    param($Executable,$Arguments,$TimeoutSeconds,$LogLabel)
    $script:CapturedArguments=@($Arguments)
    return $script:ListResult
}
$script:ListResult=[pscustomobject]@{TimedOut=$false; ExitCode=0; Stdout=@('AppA','AppB'); Stderr=@(); OutPath='list.log'; ErrPath='error.log'}
$found=@(Get-RuckZuckPending -Executable 'fake' -ScopeArgs @('--user') -DelayDays 5)
if(($found -join ',') -ne 'AppA,AppB' -or '--delay=5' -notin $script:CapturedArguments -or '--user' -notin $script:CapturedArguments){throw 'Consulta o delay incorrectos'}
foreach($kind in @('exit','timeout','stderr','invalid')) {
    $script:ListResult=[pscustomobject]@{TimedOut=($kind -eq 'timeout'); ExitCode=$(if($kind -eq 'exit'){1}else{0}); Stdout=$(if($kind -eq 'invalid'){@('unexpected output with spaces')}else{@()}); Stderr=$(if($kind -eq 'stderr'){@('access denied')}else{@()}); OutPath='list.log'; ErrPath='error.log'}
    $failed=$false
    try { Get-RuckZuckPending -Executable 'fake' -ScopeArgs @() | Out-Null } catch {$failed=$true}
    if(-not $failed){throw "Consulta $kind no detectada"}
}

function Test-Internet {param([switch]$VerboseMode) return $true}
function Download-RZGet {return 'fake-rzget.exe'}
function Get-RuckZuckPending {
    param($Executable,$ScopeArgs,[int]$DelayDays=0,$LogLabel)
    $script:Scans.Add("$LogLabel|$DelayDays")
    if($script:ScanFails){throw 'Fallo de consulta'}
    if($LogLabel -like 'verificacion-*'){return @()}
    return @('AppA','SkipMe','AppB')
}
function Invoke-RuckZuckProcess {
    param($Executable,$Arguments,$TimeoutSeconds,$LogLabel)
    $short=$Arguments[1]; $script:Calls.Add($short)
    if($script:TimeoutFirst){return [pscustomobject]@{TimedOut=$true; ExitCode=$null; Stdout=@(); Stderr=@(); OutPath='timeout.log'; ErrPath='error.log'}}
    if($short -eq 'AppA'){$lines=@('[12:00:00 INF] Installation finished: AppA')} else {$lines=@('[12:00:00 ERR] Installation failed: AppB','[12:00:00 INF] Dependency installation finished: AppB')}
    return [pscustomobject]@{TimedOut=$false; ExitCode=0; Stdout=$lines; Stderr=@(); OutPath="$short.log"; ErrPath="$short.err"}
}
function Reset-Test {
    $script:Failures=[Collections.Generic.List[string]]::new(); $script:Successes=[Collections.Generic.List[string]]::new(); $script:Skipped=[Collections.Generic.List[string]]::new()
    $script:Calls=[Collections.Generic.List[string]]::new(); $script:Scans=[Collections.Generic.List[string]]::new()
    $script:ScanFails=$false; $script:TimeoutFirst=$false
}
Reset-Test
Update-RuckZuckApps
if(($script:Calls -join ',') -ne 'AppA,AppB'){throw 'No se respeto exclusion o continuidad'}
if($script:Successes.Count -ne 1 -or $script:Successes[0] -notmatch 'AppA'){throw 'No se verifico AppA'}
if($script:Failures.Count -ne 1 -or $script:Failures[0] -notmatch 'AppB'){throw 'Exit 0 de instalacion fallida fue marcado como exito'}
if($script:Scans.Count -ne 2 -or $script:Scans[0] -notmatch '\|5$' -or $script:Scans[1] -notmatch '\|0$'){throw 'Numero de consultas o delay incorrectos'}
Reset-Test; $script:TimeoutFirst=$true
Update-RuckZuckApps
if($script:Calls.Count -ne 1 -or $script:Failures.Count -ne 1){throw 'No se detuvo tras timeout'}
Reset-Test; $script:ScanFails=$true
Update-RuckZuckApps
if($script:Failures.Count -ne 1 -or $script:Calls.Count -ne 0){throw 'Error de consulta no registrado'}
'PASS: proceso y timeout reales de prueba; exclusiones, exit 0 falso, verificacion posterior, delay y fallo de consulta simulados.'
