# Ejecutar con pwsh -NoProfile -File tests/PowerShell7Relaunch.Tests.ps1 (o con powershell.exe para probar 5.1).
# Solo ejecuta un script de prueba con pwsh; no instala PowerShell 7 ni ejecuta actualizaciones.
$ErrorActionPreference='Stop'
$file=Join-Path (Split-Path $PSScriptRoot -Parent) 'UpdateAppsDrivers8.1.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
foreach($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Find-PwshPath','Get-PwshRelaunchArguments')},$true)){ . ([scriptblock]::Create($definition.Extent.Text)) }

# PATH sin pwsh, como el de un proceso abierto antes de instalar PowerShell 7: se recarga del registro.
$originalPath=$env:Path
try {
    $env:Path="$env:SystemRoot\System32"
    $found=Find-PwshPath
    if(-not $found -or -not (Test-Path -LiteralPath $found)){throw 'Find-PwshPath no encontro pwsh.exe con un PATH desactualizado'}
} finally { $env:Path=$originalPath }

$root=Join-Path ([IO.Path]::GetTempPath()) ('pwsh relaunch '+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
try {
    # Script de prueba con el mismo param() que el real: informa lo que recibe.
    $paramBlock=$ast.ParamBlock.Extent.Text
    $probe=Join-Path $root 'Probe Updater.ps1'
    Set-Content -LiteralPath $probe -Encoding UTF8 -Value @"
[CmdletBinding()]
$paramBlock
`$data=[ordered]@{OutputFolder=`$OutputFolder; ExcludeIds=(`$ExcludeIds -join '|'); DryRun=[bool]`$DryRun; SkipStore=[bool]`$SkipStore; Verbose=[bool]`$PSBoundParameters['Verbose']; RebootPolicy=`$RebootPolicy; LogRetentionDays=`$LogRetentionDays; Major=`$PSVersionTable.PSVersion.Major}
`$data | ConvertTo-Json -Compress
exit 7
"@
    $script:UpdaterScriptPath=$probe
    $SkipStore=$true; $DryRun=$true; $script:VerboseRequested=$true
    $ExcludeIds=@('Npcap.Npcap','Foo Bar'); $RebootPolicy='IfPending'; $LogRetentionDays=15
    $OutputFolder="$root\"
    $relaunchArgs=Get-PwshRelaunchArguments
    $output=& $found @relaunchArgs
    if($LASTEXITCODE -ne 7){throw "Codigo de salida no propagado: $LASTEXITCODE"}
    $result=($output | Select-Object -Last 1) | ConvertFrom-Json
    if($result.Major -lt 7){throw 'El script de prueba no corrio en PowerShell 7'}
    if((Resolve-Path -LiteralPath $result.OutputFolder).Path.TrimEnd('\') -ne $root){throw "OutputFolder alterado: $($result.OutputFolder)"}
    if($result.ExcludeIds -ne 'Npcap.Npcap,Foo Bar'){throw "ExcludeIds alterado: $($result.ExcludeIds)"}
    if(-not $result.DryRun -or -not $result.SkipStore -or -not $result.Verbose){throw 'Faltan switches en el relanzamiento'}
    if($result.RebootPolicy -ne 'IfPending' -or $result.LogRetentionDays -ne 15){throw 'Parametros con valor alterados'}
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
"PASS: pwsh encontrado con PATH desactualizado y argumentos intactos al relanzar (PowerShell $($PSVersionTable.PSVersion.Major))."
