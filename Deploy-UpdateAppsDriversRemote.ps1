#requires -Version 5.1
<#
.SYNOPSIS
  Distribuye UpdateAppsDrivers8.1.ps1 por WinRM y programa una ejecucion puntual.
.DESCRIPTION
  Solicita credenciales una vez, no las guarda y registra la tarea como SYSTEM.
  La fecha y hora se interpretan en la zona horaria local de cada destino.
.EXAMPLE
  .\Deploy-UpdateAppsDriversRemote.ps1 -ComputerName PC01,SRV01 -UpdateAt '2026-11-15 22:00'
.EXAMPLE
  .\Deploy-UpdateAppsDriversRemote.ps1 -ComputerListPath .\equipos.txt -UpdateAt '2026-11-15 22:00' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [string[]]$ComputerName,
    [string]$ComputerListPath,
    [string]$UpdateAt,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$SourceScript = (Join-Path $PSScriptRoot 'UpdateAppsDrivers8.1.ps1'),
    [string]$RemoteFolder = 'C:\ProgramData\GenIT\UpdateAppsDrivers'
)

function ConvertTo-UpdaterDate {
    param([Parameter(Mandatory=$true)][string]$Value)
    $parsed=[datetime]::MinValue
    if (-not [datetime]::TryParseExact($Value, 'yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)) {
        throw 'Fecha invalida. Utilice yyyy-MM-dd HH:mm, por ejemplo 2026-11-15 22:00.'
    }
    return $parsed
}

function Get-UpdaterTargets {
    param([string[]]$Names, [string]$ListPath)
    $result=@($Names | ForEach-Object { $_ -split '[,;]' })
    if ($ListPath) {
        $result+=@(Get-Content -LiteralPath $ListPath -ErrorAction Stop | Where-Object { $_ -notmatch '^\s*(#|$)' } | ForEach-Object { $_ -split '[,;]' })
    }
    $result=@($result | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
    foreach ($name in $result) {
        if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9.\-]{0,252}$') { throw "Nombre de equipo invalido: $name" }
    }
    return $result
}

function Invoke-UpdaterDeployment {
    param([string]$Target, [datetime]$Date, [System.Management.Automation.PSCredential]$DomainCredential,
          [string]$LocalScript, [string]$DestinationFolder, [string]$ExpectedHash)
    $session=$null
    $stageFile=$null
    try {
        $session=New-PSSession -ComputerName $Target -Credential $DomainCredential -Authentication Negotiate -ErrorAction Stop
        $dateText=$Date.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)
        $taskName='GenIT-UpdateAppsDrivers-Once-'+$Date.ToString('yyyyMMdd-HHmm')
        $prepare=Invoke-Command -Session $session -ErrorAction Stop -ArgumentList $DestinationFolder,$dateText,$taskName -ScriptBlock {
            param($folder,$when,$name)
            $ErrorActionPreference='Stop'
            $localDate=[datetime]::ParseExact($when, 'yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)
            if ($localDate -le (Get-Date).AddMinutes(1)) { throw 'La fecha debe ser futura en el horario local del equipo, con al menos un minuto de margen.' }
            # Una tarea propia ya creada (despliegue repetido) se conserva y solo se actualiza el script.
            $reuse=$false
            $existingTask=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
            if ($existingTask) {
                $scriptArgument='"'+(Join-Path $folder 'UpdateAppsDrivers8.1.ps1')+'"'
                if ($existingTask.Description -ne 'Ejecucion puntual del actualizador GenIT' -or -not @($existingTask.Actions | Where-Object { "$($_.Arguments)".Contains($scriptArgument) }).Count) { throw "La tarea $name ya existe y no es de este despliegue; no sera reemplazada." }
                if ("$($existingTask.State)" -eq 'Running') { throw "La tarea $name se esta ejecutando; reintente cuando termine." }
                $reuse=$true
            }
            if (-not (Test-Path -LiteralPath $folder)) { New-Item -Path $folder -ItemType Directory -Force -ErrorAction Stop | Out-Null }
            $existingConfig=Join-Path $folder 'UpdateAppsDrivers8.1.config.json'
            if (Test-Path -LiteralPath $existingConfig) {
                try {
                    $parsedConfig=Get-Content -LiteralPath $existingConfig -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    if ($null -eq $parsedConfig -or $parsedConfig -isnot [pscustomobject]) { throw 'Se requiere un objeto JSON.' }
                }
                catch { throw "La configuracion existente no es JSON valido: $existingConfig. $($_.Exception.Message)" }
            }
            $stage=Join-Path $folder ('UpdateAppsDrivers8.1.'+[guid]::NewGuid().ToString('N')+'.staging')
            [pscustomobject]@{Stage=$stage; Reuse=$reuse; TimeZone=(Get-TimeZone).Id; LocalTime=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss')}
        }
        $stageFile=$prepare.Stage
        Copy-Item -LiteralPath $LocalScript -Destination $stageFile -ToSession $session -Force -ErrorAction Stop
        $result=Invoke-Command -Session $session -ErrorAction Stop -ArgumentList $DestinationFolder,$stageFile,$ExpectedHash,$dateText,$taskName,$prepare.Reuse -ScriptBlock {
            param($folder,$stage,$expected,$when,$name,$reuse)
            $ErrorActionPreference='Stop'
            if ((Get-FileHash -LiteralPath $stage -Algorithm SHA256 -ErrorAction Stop).Hash -ne $expected) { throw 'El SHA-256 de la copia remota no coincide con el archivo de origen.' }
            $localDate=[datetime]::ParseExact($when, 'yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)
            if ($localDate -le (Get-Date).AddMinutes(1)) { throw 'La fecha ya no tiene al menos un minuto de margen.' }
            # La tarea pudo cambiar entre los dos pasos: se valida de nuevo.
            $existingTask=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
            if ($existingTask -and -not $reuse) { throw "La tarea $name ya existe; no sera reemplazada." }
            if ($reuse) {
                if (-not $existingTask) { throw "La tarea $name desaparecio durante el despliegue; reintente." }
                if ("$($existingTask.State)" -eq 'Running') { throw "La tarea $name se esta ejecutando; reintente cuando termine." }
            }
            $destination=Join-Path $folder 'UpdateAppsDrivers8.1.ps1'
            $configuration=Join-Path $folder 'UpdateAppsDrivers8.1.config.json'
            $backup=$null
            if (Test-Path -LiteralPath $destination) {
                $backup=$destination+'.backup-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N')
                Copy-Item -LiteralPath $destination -Destination $backup -ErrorAction Stop
            }
            Move-Item -LiteralPath $stage -Destination $destination -Force -ErrorAction Stop
            if (-not (Test-Path -LiteralPath $configuration)) {
                $settings=[ordered]@{
                    AskQuestions=$false; SkipStore=$false; SkipPackages=@(); InstallWinGetIfMissing=$true
                    Drivers=[ordered]@{ Sources=@('Oem','Intel','WindowsUpdate'); IncludeFirmware=$false; InstallVendorTool=$true; SkipIntelIds=@(); InstallTimeoutSeconds=3600 }
                    Schedule=[ordered]@{ Enabled=$false; DayOfWeek='Sunday'; Time='22:00' }
                }
                $settings | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $configuration -Encoding UTF8 -ErrorAction Stop
            }
            if ($reuse) {
                return [pscustomobject]@{TaskName=$name; ScriptPath=$destination; ConfigPath=$configuration; Backup=$backup; Hash=$expected; Reused=$true}
            }
            $powerShell=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
            if (-not (Test-Path -LiteralPath $powerShell)) { throw 'Windows PowerShell 5.1 no esta disponible en el destino.' }
            $arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -ScheduledRun -SkipScheduleTask -SkipLegacyTaskMigration -OutputFolder "{1}"' -f $destination,$folder
            $action=New-ScheduledTaskAction -Execute $powerShell -Argument $arguments -WorkingDirectory $folder -ErrorAction Stop
            $trigger=New-ScheduledTaskTrigger -Once -At $localDate -ErrorAction Stop
            $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest -ErrorAction Stop
            $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 4) -ErrorAction Stop
            Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Ejecucion puntual del actualizador GenIT' -ErrorAction Stop | Out-Null
            [pscustomobject]@{TaskName=$name; ScriptPath=$destination; ConfigPath=$configuration; Backup=$backup; Hash=$expected; Reused=$false}
        }
        $stageFile=$null
        if ($result.Reused) {
            return [pscustomobject]@{ Equipo=$Target; Estado='Actualizado'; FechaLocal=$dateText; ZonaHoraria=$prepare.TimeZone; HoraEquipo=$prepare.LocalTime; Tarea=$result.TaskName; Script=$result.ScriptPath; Respaldo=$result.Backup; Detalle='Script actualizado; se conserva la tarea ya programada para esa fecha.' }
        }
        return [pscustomobject]@{ Equipo=$Target; Estado='Programado'; FechaLocal=$dateText; ZonaHoraria=$prepare.TimeZone; HoraEquipo=$prepare.LocalTime; Tarea=$result.TaskName; Script=$result.ScriptPath; Respaldo=$result.Backup; Detalle='Verificar resultado en el Programador y en la carpeta Logs del destino.' }
    } catch {
        $detail=$_.Exception.Message
        if ($stageFile) { $detail += " La copia pudo quedar en $DestinationFolder; revise el archivo .staging o el respaldo antes de reintentar." }
        return [pscustomobject]@{ Equipo=$Target; Estado='Error'; FechaLocal=$Date.ToString('yyyy-MM-dd HH:mm'); ZonaHoraria=$null; HoraEquipo=$null; Tarea=$null; Script=$null; Respaldo=$null; Detalle=$detail }
    } finally {
        if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        if (-not $ComputerName -and -not $ComputerListPath) { $ComputerName=@(Read-Host 'Equipos o servidores (nombres DNS separados por coma)') }
        $targets=@(Get-UpdaterTargets -Names $ComputerName -ListPath $ComputerListPath)
        if (-not $targets.Count) { throw 'No se indicaron equipos.' }
        if (-not $UpdateAt) { $UpdateAt=Read-Host 'Fecha y hora local de cada destino (yyyy-MM-dd HH:mm)' }
        $date=ConvertTo-UpdaterDate -Value $UpdateAt
        if ($RemoteFolder -notmatch '^[A-Za-z]:\\[^"\r\n*?]*$') { throw 'RemoteFolder debe ser una ruta absoluta local de Windows sin comillas ni comodines.' }
        $source=(Resolve-Path -LiteralPath $SourceScript -ErrorAction Stop).ProviderPath
        $sourceHash=(Get-FileHash -LiteralPath $source -Algorithm SHA256 -ErrorAction Stop).Hash
        $tokens=$null; $errors=$null
        $sourceAst=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
        if ($errors.Count) { throw 'El actualizador de origen tiene errores de sintaxis.' }
        if (-not @($sourceAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'SkipLegacyTaskMigration' }).Count) { throw 'El actualizador de origen no admite -SkipLegacyTaskMigration. Use la version actualizada incluida en el proyecto.' }
        Write-Host "Se programara una ejecucion para $UpdateAt, segun la zona horaria local de cada destino." -ForegroundColor Cyan
        if (-not $WhatIfPreference -and -not $Credential) { $Credential=Get-Credential -Message 'Credenciales de dominio con administracion en los destinos' }
        if (-not $WhatIfPreference -and -not $Credential) { throw 'No se proporcionaron credenciales.' }
        $results=foreach($target in $targets) {
            if ($PSCmdlet.ShouldProcess($target,"Copiar actualizador y programar ejecucion puntual para $UpdateAt")) {
                Write-Host "Procesando $target..." -ForegroundColor Cyan
                Invoke-UpdaterDeployment -Target $target -Date $date -DomainCredential $Credential -LocalScript $source -DestinationFolder $RemoteFolder -ExpectedHash $sourceHash
            }
        }
        $results | Format-Table Equipo,Estado,FechaLocal,ZonaHoraria,Tarea,Detalle -Wrap -AutoSize
        if (@($results | Where-Object Estado -eq 'Error').Count) { exit 1 }
    } catch { Write-Error $_.Exception.Message; exit 1 }
}
