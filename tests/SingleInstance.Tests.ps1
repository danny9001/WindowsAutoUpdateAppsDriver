$ErrorActionPreference='Stop'
$file=Join-Path (Split-Path $PSScriptRoot -Parent) 'UpdateAppsDrivers8.1.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
$definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Enter-UpdaterSingleInstance'},$true)
. ([scriptblock]::Create($definition.Extent.Text))
function Write-Diag($msg) {}

# Mutex con nombre de prueba (Local\) para no chocar con una ejecucion real del actualizador.
$name='Local\GenIT-UpdateAppsDrivers-Test-'+[guid]::NewGuid().ToString('N')
$first=Enter-UpdaterSingleInstance -Name $name
if(-not ($first -is [Threading.Mutex])){throw 'No se tomo el mutex libre'}
try {
    # Otro proceso no puede tomarlo mientras este lo tiene.
    $probe="`$m=[Threading.Mutex]::new(`$false,'$name'); if(`$m.WaitOne(0)){exit 0}else{exit 2}"
    $pwsh=(Get-Process -Id $PID).Path
    & $pwsh -NoProfile -Command $probe
    if($LASTEXITCODE -ne 2){throw "Otro proceso tomo el mutex ocupado (codigo $LASTEXITCODE)"}
} finally {
    $first.ReleaseMutex(); $first.Dispose()
}
$again=Enter-UpdaterSingleInstance -Name $name
if(-not ($again -is [Threading.Mutex])){throw 'No se volvio a tomar el mutex liberado'}
$again.ReleaseMutex(); $again.Dispose()
'PASS: mutex libre, ocupado por otro proceso y liberado.'
