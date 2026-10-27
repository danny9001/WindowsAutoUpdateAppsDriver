$ErrorActionPreference='Stop'
$file=Join-Path (Split-Path $PSScriptRoot -Parent) 'UpdateAppsDrivers8.1.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
foreach($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Write-Diag','Invoke-DriverProcess','Write-DiagnosticContext','Get-PendingReboot','Get-IsServer','Test-IsAdmin')},$true)){ . ([scriptblock]::Create($definition.Extent.Text)) }
function Write-WarnMsg($msg) {}

# Solo procesos inofensivos y lecturas del sistema; no se instala ni modifica nada.
$script:DiagMode=$false
$silent=@(Write-Diag 'no debe verse' 6>&1)
if($silent.Count){throw 'Write-Diag escribio con el modo detallado desactivado'}

$script:DiagMode=$true
$line="$(@(Write-Diag 'mensaje de prueba' 6>&1)[0])"
if($line -notmatch '^\s*\[diag \d{2}:\d{2}:\d{2}\] mensaje de prueba$'){throw "Formato de Write-Diag incorrecto: $line"}

$pwsh=(Get-Command pwsh.exe -ErrorAction Stop).Source
$lines=@(Invoke-DriverProcess -FilePath $pwsh -Arguments @('-NoProfile','-Command','exit 3') -TimeoutSeconds 30 6>&1 | ForEach-Object { "$_" })
if(-not ($lines -match 'Ejecutando: ".*pwsh\.exe" -NoProfile -Command exit 3') -or -not ($lines -match 'termino con codigo 3 en [\d.,]+ s')){throw "Registro de proceso incompleto: $($lines -join ' / ')"}

$script:UpdaterScriptPath=$file; $OutputFolder=$env:TEMP; $RebootPolicy='None'; $ScheduledRun=$false; $DryRun=$true; $script:DriverRebootRequired=$false
$script:UpdaterConfig=[pscustomobject]@{Verbose=$true; Drivers=[pscustomobject]@{Sources=@('Oem')}}
$context=@(Write-DiagnosticContext 6>&1 | ForEach-Object { "$_" })
foreach($expected in @('SHA-256 del script: [0-9A-F]{64}','PowerShell ','Windows: ','Usuario: ','Configuracion efectiva: .*"Verbose":true','NoDefaultCurrentDirectoryInExePath: ')){
    if(-not ($context -match $expected)){throw "Falta en el contexto: $expected"}
}
$script:DiagMode=$false
if(@(Write-DiagnosticContext 6>&1).Count){throw 'Contexto escrito con el modo detallado desactivado'}
'PASS: Write-Diag silencioso y con formato, registro de comando, codigo y duracion, contexto del equipo.'
