$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $repo 'UpdateAppsDrivers8.1.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
foreach($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Initialize-UpdaterConfiguration','Save-UpdaterConfiguration')},$true)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
function Write-Info($msg) {}
$testDirectory=Join-Path ([IO.Path]::GetTempPath()) ('updater-config-tests-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDirectory | Out-Null
$script:UpdaterScriptPath=Join-Path $testDirectory 'UpdateAppsDrivers8.1.ps1'
Initialize-UpdaterConfiguration
if(-not (Test-Path -LiteralPath $script:UpdaterConfigPath) -or $script:UpdaterConfig.AskQuestions -or $script:UpdaterConfig.Schedule.Enabled){throw 'Valores predeterminados incorrectos'}
$script:UpdaterConfig.SkipPackages=@('Microsoft.VCRedist.2015+.x64')
$script:UpdaterConfig.SkipStore=$true
$script:UpdaterConfig.Schedule.Enabled=$true
$script:UpdaterConfig.Schedule.DayOfWeek='Friday'
$script:UpdaterConfig.Schedule.Time='03:15'
$script:UpdaterConfig.RuckZuck.SkipShortNames=@('Firefox')
$script:UpdaterConfig.RuckZuck.DelayDays=5
if(($script:UpdaterConfig.Drivers.Sources -join ',') -ne 'Oem,Intel,WindowsUpdate' -or -not $script:UpdaterConfig.Drivers.IncludeFirmware){throw 'Valores predeterminados de Drivers incorrectos'}
$script:UpdaterConfig.Drivers.Sources=@('Intel')
$script:UpdaterConfig.Drivers.SkipIntelIds=@('929468')
$script:UpdaterConfig.Verbose=$true
Save-UpdaterConfiguration
Initialize-UpdaterConfiguration
if($script:UpdaterConfig.SkipPackages[0] -ne 'Microsoft.VCRedist.2015+.x64' -or -not $script:UpdaterConfig.SkipStore -or $script:UpdaterConfig.Schedule.Time -ne '03:15' -or $script:UpdaterConfig.RuckZuck.SkipShortNames[0] -ne 'Firefox' -or $script:UpdaterConfig.RuckZuck.DelayDays -ne 5){throw 'No se conservaron las decisiones'}
if(($script:UpdaterConfig.Drivers.Sources -join ',') -ne 'Intel' -or $script:UpdaterConfig.Drivers.SkipIntelIds[0] -ne '929468' -or -not $script:UpdaterConfig.Verbose){throw 'No se conservo la configuracion de Drivers o Verbose'}
$validConfig=Get-Content -LiteralPath $script:UpdaterConfigPath -Raw
foreach($invalid in @('{invalid json}', '{"AskQuestions":"false"}', '{"SkipPackages":"Test.App"}', '{"Schedule":{"Time":"25:00"}}', '{"Schedule":{"DayOfWeek":"monday"}}', '{"RuckZuck":{"SkipShortNames":"Firefox"}}', '{"RuckZuck":{"InstallTimeoutSeconds":1}}', '{"RuckZuck":{"DelayDays":"5"}}', '{"Drivers":{"Sources":["Nvidia"]}}', '{"Drivers":{"Sources":"Oem"}}', '{"Drivers":{"IncludeFirmware":"true"}}', '{"Drivers":{"SkipIntelIds":["abc"]}}', '{"Drivers":{"InstallTimeoutSeconds":5}}', '{"Verbose":"true"}')) {
    Set-Content -LiteralPath $script:UpdaterConfigPath -Value $invalid
    $rejected=$false
    try { Initialize-UpdaterConfiguration } catch {$rejected=$true}
    if(-not $rejected){throw "Se acepto configuracion invalida: $invalid"}
}
Set-Content -LiteralPath $script:UpdaterConfigPath -Value $validConfig
Initialize-UpdaterConfiguration
'PASS: creacion de JSON, valores sin preguntas, persistencia y rechazo de configuracion invalida.'
# Directorio temporal aislado conservado para diagnostico; nunca modifica tareas ni instaladores.
