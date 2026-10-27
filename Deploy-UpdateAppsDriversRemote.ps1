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
.EXAMPLE
  .\Deploy-UpdateAppsDriversRemote.ps1 -ComputerListPath .\equipos.txt -RunNow -UpdaterVerbose
  Inicia ya la actualizacion en todos los destinos a la vez, en modo detallado.
.EXAMPLE
  .\Deploy-UpdateAppsDriversRemote.ps1 -ComputerListPath .\equipos.txt -CollectLogs
  Copia los logs de las ultimas 24 horas a Logs\Remote\<equipo> e informa el estado de las tareas.
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
    [string[]]$ComputerName,
    [string]$ComputerListPath,
    [string]$UpdateAt,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$SourceScript = (Join-Path $PSScriptRoot 'UpdateAppsDrivers8.1.ps1'),
    [string]$RemoteFolder = 'C:\ProgramData\GenIT\UpdateAppsDrivers',
    [switch]$RunNow,
    [switch]$UpdaterVerbose,
    [switch]$CollectLogs,
    [ValidateRange(1,720)][int]$LogHours = 24,
    [string]$LocalLogFolder = (Join-Path $PSScriptRoot 'Logs\Remote')
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
          [string]$LocalScript, [string]$DestinationFolder, [string]$ExpectedHash, [switch]$RunNow, [switch]$UpdaterVerbose)
    $session=$null
    $stageFile=$null
    try {
        $session=New-PSSession -ComputerName $Target -Credential $DomainCredential -Authentication Negotiate -ErrorAction Stop
        if ($RunNow) {
            # Sin fecha: tarea sin disparador que se inicia al terminar el despliegue.
            $dateText=''
            $taskName='GenIT-UpdateAppsDrivers-Now-'+(Get-Date -Format 'yyyyMMdd-HHmmss')
        } else {
            $dateText=$Date.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)
            $taskName='GenIT-UpdateAppsDrivers-Once-'+$Date.ToString('yyyyMMdd-HHmm')
        }
        $prepare=Invoke-Command -Session $session -ErrorAction Stop -ArgumentList $DestinationFolder,$dateText,$taskName -ScriptBlock {
            param($folder,$when,$name)
            $ErrorActionPreference='Stop'
            if ($when) {
                $localDate=[datetime]::ParseExact($when, 'yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)
                if ($localDate -le (Get-Date).AddMinutes(1)) { throw 'La fecha debe ser futura en el horario local del equipo, con al menos un minuto de margen.' }
            }
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
        $result=Invoke-Command -Session $session -ErrorAction Stop -ArgumentList $DestinationFolder,$stageFile,$ExpectedHash,$dateText,$taskName,$prepare.Reuse,($UpdaterVerbose.IsPresent) -ScriptBlock {
            param($folder,$stage,$expected,$when,$name,$reuse,$verbose)
            $ErrorActionPreference='Stop'
            if ((Get-FileHash -LiteralPath $stage -Algorithm SHA256 -ErrorAction Stop).Hash -ne $expected) { throw 'El SHA-256 de la copia remota no coincide con el archivo de origen.' }
            if ($when) {
                $localDate=[datetime]::ParseExact($when, 'yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture)
                if ($localDate -le (Get-Date).AddMinutes(1)) { throw 'La fecha ya no tiene al menos un minuto de margen.' }
            }
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
            if ($verbose) { $arguments+=' -Verbose' }
            $action=New-ScheduledTaskAction -Execute $powerShell -Argument $arguments -WorkingDirectory $folder -ErrorAction Stop
            $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest -ErrorAction Stop
            $settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 4) -ErrorAction Stop
            $register=@{TaskName=$name; Action=$action; Principal=$principal; Settings=$settings; Description='Ejecucion puntual del actualizador GenIT'; ErrorAction='Stop'}
            # Ejecucion inmediata: sin disparador; el despliegue la inicia al final.
            if ($when) { $register.Trigger=New-ScheduledTaskTrigger -Once -At $localDate -ErrorAction Stop }
            Register-ScheduledTask @register | Out-Null
            [pscustomobject]@{TaskName=$name; ScriptPath=$destination; ConfigPath=$configuration; Backup=$backup; Hash=$expected; Reused=$false}
        }
        $stageFile=$null
        # Copias en otras carpetas que ejecutan las tareas del equipo (p. ej. la semanal en C:\Medios): se actualizan en su sitio.
        try {
            $copies=@(Invoke-Command -Session $session -ErrorAction Stop -ArgumentList $result.ScriptPath,$ExpectedHash -ScriptBlock {
                param($main,$expected)
                $ErrorActionPreference='Stop'
                $found=[ordered]@{}
                foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
                    foreach ($action in @($task.Actions)) {
                        foreach ($match in [regex]::Matches("$($action.Execute) $($action.Arguments)", '(?i)-File\s+(?:"([^"]+)"|(\S+))')) {
                            $path=if ($match.Groups[1].Success) { $match.Groups[1].Value } else { $match.Groups[2].Value }
                            if ((Split-Path -Path $path -Leaf) -ine 'UpdateAppsDrivers8.1.ps1') { continue }
                            if (-not [IO.Path]::IsPathRooted($path) -and $action.WorkingDirectory) { $path=Join-Path $action.WorkingDirectory $path }
                            if ($path -notmatch '^[A-Za-z]:\\') { continue }
                            try { $path=[IO.Path]::GetFullPath($path) } catch { continue }
                            if ($path -ieq $main) { continue }
                            $key=$path.ToLowerInvariant()
                            if (-not $found.Contains($key)) { $found[$key]=[pscustomobject]@{Path=$path; Tasks=[Collections.Generic.List[object]]::new()} }
                            $found[$key].Tasks.Add($task)
                        }
                    }
                }
                foreach ($entry in $found.Values) {
                    $path=$entry.Path
                    $stage=$null
                    try {
                        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'el archivo no existe' }
                        $running=@($entry.Tasks | Where-Object { "$($_.State)" -eq 'Running' } | ForEach-Object { $_.TaskName })
                        if ($running.Count) { throw "la tarea $($running -join ', ') se esta ejecutando" }
                        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash -eq $expected) {
                            [pscustomobject]@{Path=$path; Estado='al dia'; Respaldo=$null}
                            continue
                        }
                        $stage=$path+'.'+[guid]::NewGuid().ToString('N')+'.staging'
                        Copy-Item -LiteralPath $main -Destination $stage -ErrorAction Stop
                        if ((Get-FileHash -LiteralPath $stage -Algorithm SHA256 -ErrorAction Stop).Hash -ne $expected) { throw 'el SHA-256 de la copia no coincide' }
                        $copyBackup=$path+'.backup-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N')
                        Copy-Item -LiteralPath $path -Destination $copyBackup -ErrorAction Stop
                        Move-Item -LiteralPath $stage -Destination $path -Force -ErrorAction Stop
                        $stage=$null
                        [pscustomobject]@{Path=$path; Estado='actualizada'; Respaldo=$copyBackup}
                    } catch {
                        [pscustomobject]@{Path=$path; Estado="error: $($_.Exception.Message)"; Respaldo=$null}
                    } finally {
                        if ($stage) { Remove-Item -LiteralPath $stage -Force -ErrorAction SilentlyContinue }
                    }
                }
            })
        } catch {
            $copies=@([pscustomobject]@{Path='(busqueda de copias)'; Estado="error: $($_.Exception.Message)"; Respaldo=$null})
        }
        $copyText=($copies | ForEach-Object { '{0} ({1})' -f $_.Path, $_.Estado }) -join '; '
        $copyFailed=@($copies | Where-Object { $_.Estado -like 'error*' }).Count -gt 0
        if ($result.Reused) {
            $state='Actualizado'; $detail='Script actualizado; se conserva la tarea ya programada para esa fecha.'
        } else {
            $state='Programado'; $detail='Verificar resultado en el Programador y en la carpeta Logs del destino.'
        }
        if ($RunNow) {
            Invoke-Command -Session $session -ErrorAction Stop -ArgumentList $result.TaskName -ScriptBlock { param($name) Start-ScheduledTask -TaskName $name -ErrorAction Stop }
            $state='Iniciado'; $dateText=(Get-Date).ToString('yyyy-MM-dd HH:mm'); $detail='Ejecucion iniciada. Para revisarla: -CollectLogs.'
        }
        if ($copyFailed) { $state='Parcial'; $detail+=' Alguna copia existente no se actualizo; ver Copias.' }
        return [pscustomobject]@{ Equipo=$Target; Estado=$state; FechaLocal=$dateText; ZonaHoraria=$prepare.TimeZone; HoraEquipo=$prepare.LocalTime; Tarea=$result.TaskName; Script=$result.ScriptPath; Respaldo=$result.Backup; Copias=$copyText; CopiasDetalle=$copies; Detalle=$detail }
    } catch {
        $detail=$_.Exception.Message
        if ($stageFile) { $detail += " La copia pudo quedar en $DestinationFolder; revise el archivo .staging o el respaldo antes de reintentar." }
        return [pscustomobject]@{ Equipo=$Target; Estado='Error'; FechaLocal=$Date.ToString('yyyy-MM-dd HH:mm'); ZonaHoraria=$null; HoraEquipo=$null; Tarea=$null; Script=$null; Respaldo=$null; Copias=$null; CopiasDetalle=@(); Detalle=$detail }
    } finally {
        if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    }
}

function Get-UpdaterRemoteLogs {
    param([string]$Target, [System.Management.Automation.PSCredential]$DomainCredential, [string]$DestinationFolder, [string]$LocalFolder, [int]$Hours)
    $session=$null
    try {
        $session=New-PSSession -ComputerName $Target -Credential $DomainCredential -Authentication Negotiate -ErrorAction Stop
        $remote=Invoke-Command -Session $session -ErrorAction Stop -ArgumentList $DestinationFolder,$Hours -ScriptBlock {
            param($folder,$hours)
            $ErrorActionPreference='Stop'
            $own=@(Get-ScheduledTask -TaskName 'GenIT-UpdateAppsDrivers-*' -ErrorAction SilentlyContinue)
            $tasks=@($own | ForEach-Object {
                $info=$_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
                $last=if ($info -and $info.LastRunTime -and $info.LastRunTime.Year -gt 2000) { $info.LastRunTime.ToString('yyyy-MM-dd HH:mm') } else { 'nunca' }
                '{0}: {1}, ultima ejecucion {2}, resultado {3}' -f $_.TaskName, $_.State, $last, $(if ($info) { $info.LastTaskResult } else { '-' })
            })
            $logFolder=Join-Path $folder 'Logs'
            $logs=@(if (Test-Path -LiteralPath $logFolder) {
                Get-ChildItem -LiteralPath $logFolder -Filter 'Actualizar-*.log' -File | Where-Object { $_.LastWriteTime -ge (Get-Date).AddHours(-$hours) } | Sort-Object LastWriteTime | ForEach-Object { $_.FullName }
            })
            [pscustomobject]@{Tasks=$tasks; Logs=$logs; Running=@($own | Where-Object { "$($_.State)" -eq 'Running' }).Count}
        }
        $targetFolder=Join-Path $LocalFolder ($Target -replace '[^A-Za-z0-9.\-]','_')
        if (-not (Test-Path -LiteralPath $targetFolder)) { New-Item -ItemType Directory -Path $targetFolder -Force -ErrorAction Stop | Out-Null }
        # El transcript de una ejecucion en curso se puede copiar mientras se escribe.
        $copied=@(foreach ($log in @($remote.Logs)) {
            $local=Join-Path $targetFolder (Split-Path -Path $log -Leaf)
            Copy-Item -LiteralPath $log -Destination $local -FromSession $session -Force -ErrorAction Stop
            $local
        })
        return [pscustomobject]@{ Equipo=$Target; Estado=$(if ($remote.Running) { 'En ejecucion' } else { 'Sin ejecucion en curso' }); Logs=$copied.Count; Carpeta=$targetFolder; Tareas=@($remote.Tasks); Detalle=$null }
    } catch {
        return [pscustomobject]@{ Equipo=$Target; Estado='Error'; Logs=0; Carpeta=$null; Tareas=@(); Detalle=$_.Exception.Message }
    } finally {
        if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        if (-not $ComputerName -and -not $ComputerListPath) { $ComputerName=@(Read-Host 'Equipos o servidores (nombres DNS separados por coma)') }
        $targets=@(Get-UpdaterTargets -Names $ComputerName -ListPath $ComputerListPath)
        if (-not $targets.Count) { throw 'No se indicaron equipos.' }
        if (@(@($RunNow.IsPresent, $CollectLogs.IsPresent, [bool]$UpdateAt) | Where-Object { $_ }).Count -gt 1) { throw 'Use solo una de estas opciones: -UpdateAt, -RunNow o -CollectLogs.' }
        if ($CollectLogs) {
            if (-not $Credential) { $Credential=Get-Credential -Message 'Credenciales de dominio con administracion en los destinos' }
            if (-not $Credential) { throw 'No se proporcionaron credenciales.' }
            $collected=foreach ($target in $targets) {
                Write-Host "Recolectando logs de $target..." -ForegroundColor Cyan
                Get-UpdaterRemoteLogs -Target $target -DomainCredential $Credential -DestinationFolder $RemoteFolder -LocalFolder $LocalLogFolder -Hours $LogHours
            }
            $collected | Format-Table Equipo,Estado,Logs,Carpeta,Detalle -Wrap -AutoSize
            foreach ($item in @($collected | Where-Object { @($_.Tareas).Count })) {
                Write-Host "Tareas en $($item.Equipo):" -ForegroundColor Cyan
                $item.Tareas | ForEach-Object { Write-Host "  $_" }
            }
            if (@($collected | Where-Object Estado -eq 'Error').Count) { exit 1 }
            exit 0
        }
        $date=[datetime]::MinValue
        if (-not $RunNow) {
            if (-not $UpdateAt) { $UpdateAt=Read-Host 'Fecha y hora local de cada destino (yyyy-MM-dd HH:mm)' }
            $date=ConvertTo-UpdaterDate -Value $UpdateAt
        }
        if ($RemoteFolder -notmatch '^[A-Za-z]:\\[^"\r\n*?]*$') { throw 'RemoteFolder debe ser una ruta absoluta local de Windows sin comillas ni comodines.' }
        $source=(Resolve-Path -LiteralPath $SourceScript -ErrorAction Stop).ProviderPath
        $sourceHash=(Get-FileHash -LiteralPath $source -Algorithm SHA256 -ErrorAction Stop).Hash
        $tokens=$null; $errors=$null
        $sourceAst=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
        if ($errors.Count) { throw 'El actualizador de origen tiene errores de sintaxis.' }
        if (-not @($sourceAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'SkipLegacyTaskMigration' }).Count) { throw 'El actualizador de origen no admite -SkipLegacyTaskMigration. Use la version actualizada incluida en el proyecto.' }
        $when=if ($RunNow) { 'ahora' } else { $UpdateAt }
        if ($RunNow) { Write-Host 'Se iniciara la actualizacion ahora en todos los destinos, en paralelo (cada uno como SYSTEM).' -ForegroundColor Cyan }
        else { Write-Host "Se programara una ejecucion para $UpdateAt, segun la zona horaria local de cada destino." -ForegroundColor Cyan }
        if ($UpdaterVerbose) { Write-Host 'El actualizador se ejecutara en modo detallado (-Verbose).' -ForegroundColor Cyan }
        if (-not $WhatIfPreference -and -not $Credential) { $Credential=Get-Credential -Message 'Credenciales de dominio con administracion en los destinos' }
        if (-not $WhatIfPreference -and -not $Credential) { throw 'No se proporcionaron credenciales.' }
        $results=foreach($target in $targets) {
            if ($PSCmdlet.ShouldProcess($target,"Copiar actualizador, actualizar sus copias existentes y programar ejecucion puntual para $when")) {
                Write-Host "Procesando $target..." -ForegroundColor Cyan
                Invoke-UpdaterDeployment -Target $target -Date $date -DomainCredential $Credential -LocalScript $source -DestinationFolder $RemoteFolder -ExpectedHash $sourceHash -RunNow:$RunNow -UpdaterVerbose:$UpdaterVerbose
            }
        }
        $results | Format-Table Equipo,Estado,FechaLocal,ZonaHoraria,Tarea,Detalle -Wrap -AutoSize
        foreach ($item in @($results | Where-Object { @($_.CopiasDetalle).Count })) {
            Write-Host "Copias existentes en $($item.Equipo):" -ForegroundColor Cyan
            foreach ($copy in $item.CopiasDetalle) {
                Write-Host ("  {0}: {1}" -f $copy.Path, $copy.Estado) -ForegroundColor $(if ($copy.Estado -like 'error*') { 'Yellow' } else { 'Gray' })
            }
        }
        if (@($results | Where-Object { $_.Estado -in @('Error','Parcial') }).Count) { exit 1 }
    } catch { Write-Error $_.Exception.Message; exit 1 }
}
