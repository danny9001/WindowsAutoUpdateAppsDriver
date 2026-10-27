$ErrorActionPreference='Stop'
$file=Join-Path (Split-Path $PSScriptRoot -Parent) 'UpdateAppsDrivers8.1.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
foreach($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-UniqueWindowsUpdates'},$true)){ . ([scriptblock]::Create($definition.Extent.Text)) }

# Resultado simulado de Get-WindowsUpdate -Install: el mismo update en cada etapa, como en LPZVMAD01.
$defender='Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.461.230.0)'
$updates=@(
    [pscustomobject]@{KB='KB2267602'; Title=$defender; Status='A-------'},
    [pscustomobject]@{KB='KB2267602'; Title=$defender; Status='AD------'},
    [pscustomobject]@{KB='KB2267602'; Title=$defender; Status='ADI-----'},
    [pscustomobject]@{KB='KB5070001'; Title='2026-10 Cumulative Update'; Status='ADI-----'},
    $null
)
$unique=@(Get-UniqueWindowsUpdates -Updates $updates)
if($unique.Count -ne 2){throw "Se esperaban 2 actualizaciones, hay $($unique.Count)"}
if(($unique | Where-Object KB -eq 'KB2267602').Status -ne 'ADI-----'){throw 'No se conservo el ultimo estado'}
if(@(Get-UniqueWindowsUpdates -Updates @()).Count -ne 0){throw 'Lista vacia mal tratada'}
'PASS: actualizaciones repetidas por etapa contadas una vez, con su ultimo estado.'
