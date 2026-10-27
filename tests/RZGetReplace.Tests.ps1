$ErrorActionPreference='Stop'
$file=Join-Path (Split-Path $PSScriptRoot -Parent) 'UpdateAppsDrivers8.1.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
foreach($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Install-RZGetFiles','Repair-RZGetFiles')},$true)){ . ([scriptblock]::Create($definition.Extent.Text)) }
function Write-WarnMsg($msg) { $script:Warnings.Add($msg) }
$script:Warnings=[Collections.Generic.List[string]]::new()

# Solo archivos de texto en una carpeta temporal; no se descarga ni ejecuta RZGet.
$root=Join-Path ([IO.Path]::GetTempPath()) ('rzget-replace-tests-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$exe=Join-Path $root 'RZGet.exe'; $config="$exe.config"
function New-Pair {
    Get-ChildItem -LiteralPath $root -File | Remove-Item -Force
    Set-Content -LiteralPath $exe -Value 'exe-old'; Set-Content -LiteralPath $config -Value 'config-old'
    $script:Files=@(
        [pscustomobject]@{Name='RZGet.exe'; Tmp="$exe.$([guid]::NewGuid().ToString('N')).download"; Target=$exe},
        [pscustomobject]@{Name='RZGet.exe.config'; Tmp="$config.$([guid]::NewGuid().ToString('N')).download"; Target=$config}
    )
    Set-Content -LiteralPath $script:Files[0].Tmp -Value 'exe-new'; Set-Content -LiteralPath $script:Files[1].Tmp -Value 'config-new'
}
function Get-Pair { '{0}|{1}' -f (Get-Content -LiteralPath $exe -Raw).Trim(), (Get-Content -LiteralPath $config -Raw).Trim() }
function Get-Leftovers { @(Get-ChildItem -LiteralPath $root -File | Where-Object { $_.Name -match '\.(bak|download)$' }) }

try {
    New-Pair
    Install-RZGetFiles -Files $script:Files
    if((Get-Pair) -ne 'exe-new|config-new'){throw 'No se reemplazo el par'}
    if((Get-Leftovers).Count){throw 'Quedaron respaldos tras un reemplazo correcto'}

    # Falla del segundo archivo: su descarga desaparece antes de moverse.
    New-Pair
    Remove-Item -LiteralPath $script:Files[1].Tmp
    $failed=$false
    try { Install-RZGetFiles -Files $script:Files } catch { $failed=$true }
    if(-not $failed){throw 'No se informo la falla del segundo archivo'}
    if((Get-Pair) -ne 'exe-old|config-old'){throw "Reversion incompleta: $(Get-Pair)"}
    if(@(Get-Leftovers | Where-Object Extension -eq '.bak').Count){throw 'Quedaron respaldos tras la reversion'}

    # Reemplazo interrumpido: el ejecutable quedo renombrado como respaldo y hay una descarga huerfana.
    New-Pair
    Move-Item -LiteralPath $exe -Destination "$exe.$([guid]::NewGuid().ToString('N')).bak"
    Repair-RZGetFiles -Targets @($exe,$config)
    if((Get-Pair) -ne 'exe-old|config-old'){throw 'No se recupero el reemplazo interrumpido'}
    if((Get-Leftovers).Count){throw 'No se limpiaron temporales huerfanos'}
    if($script:Warnings.Count -ne 1){throw 'No se aviso la recuperacion'}

    # Respaldos viejos con el archivo presente: se borran sin pisar el actual; otros archivos no se tocan.
    New-Pair
    Set-Content -LiteralPath "$config.$([guid]::NewGuid().ToString('N')).bak" -Value 'config-older'
    Set-Content -LiteralPath (Join-Path $root 'RZGet.exe.notes.bak') -Value 'ajeno'
    Repair-RZGetFiles -Targets @($exe,$config)
    if((Get-Pair) -ne 'exe-old|config-old'){throw 'Un respaldo viejo piso el archivo actual'}
    if(-not (Test-Path -LiteralPath (Join-Path $root 'RZGet.exe.notes.bak'))){throw 'Se borro un archivo ajeno'}
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
'PASS: reemplazo del par, reversion ante falla del segundo archivo, recuperacion de reemplazo interrumpido y limpieza de huerfanos.'
