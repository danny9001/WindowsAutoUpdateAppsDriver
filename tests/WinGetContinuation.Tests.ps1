$ErrorActionPreference = 'Stop'
$file = Join-Path (Split-Path $PSScriptRoot -Parent) 'UpdateAppsDrivers8.1.ps1'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach($definition in $ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Get-ExcludedIds','Get-WinGetUpgradeItems','Get-WinGetUpgradeIds','Update-WinGetApps')},$true)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
$script:Expected=@('Microsoft.SQLServer.OLEDBDriver','Microsoft.VCRedist.2015+.x64','Microsoft.VCRedist.2015+.x86')
$script:Lines=@(
    ('{0,-70}{1,-36}{2,-16}{3,-16}{4}' -f 'Name','Id','Version','Available','Source'),
    ('-' * 145),
    ('{0,-70}{1,-36}{2,-16}{3,-16}{4}' -f 'Microsoft OLE DB Driver for SQL Server',$script:Expected[0],'18.7.5.0','19.4.3','winget'),
    ('{0,-70}{1,-36}{2,-16}{3,-16}{4}' -f 'Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.44.35211',$script:Expected[1],'14.44.35211.0','14.51.36247.0','winget'),
    ('{0,-70}{1,-36}{2,-16}{3,-16}{4}' -f 'Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.36.32532',$script:Expected[2],'14.36.32532.0','14.51.36247.0','winget'),
    '3 upgrades available.'
)
$ids=@(Get-WinGetUpgradeIds -Lines $script:Lines)
if (($ids -join ',') -ne ($script:Expected -join ',')) { throw "IDs incorrectos: $ids" }
function Write-Info($msg) {}
function Write-Section { param($Number,$Total,$Title) }
function Write-Detail($msg) {}
function Get-WinGetUpgradeFlags { return @() }
$DryRun=$false; $AllowReinstall=$false
$script:Failures=[Collections.Generic.List[string]]::new(); $script:Successes=[Collections.Generic.List[string]]::new(); $script:Skipped=[Collections.Generic.List[string]]::new()
function Write-Ok($msg) {}
function Write-WarnMsg($msg) {}
function Write-ErrMsg($msg) { throw $msg }
function Test-WinGetInstalled { return $true }
function Test-Internet { param([switch]$VerboseMode) return $true }
function Ensure-WinGetSources {}
function Resolve-WinGetFailure { param($Id,$Details,$Operation) }
function Get-WinGetUpgradesList { return $script:Lines }
function Invoke-WinGet {
    $id=$args[2]
    $script:Attempts.Add($id)
    if ($id -eq $script:Expected[0]) {
        if ($script:ThrowFirst) { throw 'Installer failure' }
        $global:LASTEXITCODE=-1978335159
    } else { $global:LASTEXITCODE=0 }
}
$ForceWinGetReinstall=$false
$script:UpdaterConfig=[pscustomobject]@{SkipPackages=@()}
foreach($mode in @($false,$true)) {
    $script:ThrowFirst=$mode
    $script:Attempts=[Collections.Generic.List[string]]::new()
    Update-WinGetApps
    if (($script:Attempts -join ',') -ne ($script:Expected -join ',')) { throw "No continuo todos los paquetes: $script:Attempts" }
}
$script:UpdaterConfig.SkipPackages=@('Microsoft.SQLServer.OLEDBDriver')
$script:Attempts=[Collections.Generic.List[string]]::new()
Update-WinGetApps
if (($script:Attempts -join ',') -ne ($script:Expected[1..2] -join ',')) { throw 'No se respeto SkipPackages' }
Write-Output 'PASS: IDs con +, continuidad tras codigo 1603/WinGet y excepcion, tres paquetes intentados.'

