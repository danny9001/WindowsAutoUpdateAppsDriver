# WindowsAutoUpdateAppsDriver

[EN](#en-version) · [ES](#es-version)

---

# EN VERSION

`UpdateAppsDrivers8.1.ps1` automatically updates applications, Microsoft Store apps, drivers and Windows on a Windows machine, and can schedule itself as a weekly task.

## Requirements

- Windows 10/11 or Windows Server 2019+ (Desktop Experience). Windows PowerShell 5.1 is enough to start: the script relaunches itself in PowerShell 7 and installs it if missing.
- Internet connection.
- Administrator rights for Windows Update, installing PowerShell 7/WinGet and creating the scheduled task.

## What it does

The run is organised in four numbered steps:

1. **RuckZuck (RZGet)** – checks the *machine* and *user* scopes separately and updates each app one by one.
2. **WinGet** – lists pending upgrades in a table, then upgrades package by package (one failure never blocks the rest). Installs WinGet automatically if missing (LTSC/Server included).
3. **Microsoft Store** – `wsreset` + `winget upgrade --source msstore`. Skipped on Windows Server and in scheduled runs.
4. **Windows Update** – patches and drivers through the `PSWindowsUpdate` module.

At the end it prints a summary (successful / skipped / with problems / reboot pending) and exits with code `1` if anything failed, so the Task Scheduler shows the real status.

## Usage

```powershell
# Interactive run (asks once whether to create the weekly task)
.\UpdateAppsDrivers8.1.ps1

# Only list what is pending, install nothing
.\UpdateAppsDrivers8.1.ps1 -DryRun

# Do not ask about the scheduled task
.\UpdateAppsDrivers8.1.ps1 -SkipScheduleTask
```

## Parameters

| Parameter | Description |
|---|---|
| `-DryRun` | Only list pending updates; installs nothing. |
| `-SkipScheduleTask` | Never ask about the scheduled task. |
| `-ReconfigureTask` | Change day/time of an existing task (by default it is not asked again). |
| `-ScheduledRun` | Used by the scheduled task: no questions, installs WinGet if missing. |
| `-SkipStore` | Skip Microsoft Store steps. |
| `-IncludePinned` | Also upgrade pinned WinGet packages (respected by default). |
| `-IncludeUnknown` | Include WinGet packages with unknown version (skipped by default). |
| `-AllowReinstall` | Allow uninstall + reinstall when WinGet reports a different install technology (off by default). |
| `-ExcludeIds` | WinGet IDs to skip, comma separated. A file `exclusiones.txt` (one ID per line, `#` for comments) next to the script is also read. |
| `-RebootPolicy` | `None` (default, only warns) or `IfPending` (reboots after 60 s if a reboot is pending). |
| `-LogRetentionDays` | Days to keep `Logs\Actualizar-*.log` (default 30). |
| `-ForceWinGetReinstall` | Reinstall WinGet even if available. |
| `-NoRelaunch` | Do not relaunch in PowerShell 7. |
| `-OutputFolder` | Folder for downloads and the `Logs` subfolder (default: script folder). |

## Scheduled task

On the first interactive run the script offers to create a weekly task (`UpdateAppsDrivers8.1-<hash>`) that runs as SYSTEM at the day and time you choose. It runs on battery, only if the network is available, and has a 4-hour limit. Once it exists the script does not ask again; use `-ReconfigureTask` to change it. Keep the script in the same path the task points to.

## Logs and safety

- Transcripts and the manual recovery log are written to `Logs\` next to the script and rotated by age.
- Downloaded installers (PowerShell 7 MSI, VC++ redistributable, WinGet bundle) must carry a valid Microsoft signature; `RZGet.exe` is checked and only warns.
- Packages that publishers do not allow to be upgraded with WinGet (e.g. Android Studio) are reported as *skipped*, not as failures.

## Tests

```powershell
pwsh -NoProfile -File tests/ScheduledTask.Tests.ps1
pwsh -NoProfile -File tests/WinGetContinuation.Tests.ps1
pwsh -NoProfile -File tests/WinGetRecovery.Tests.ps1
```

They extract functions from the script and mock cmdlets; they do not update anything or register real tasks.

## Credits

- **Author:** Daniel Landivar – danny9001@gmail.com
- **License:** CC BY-NC (Attribution-NonCommercial)
- **Editor:** Microsoft Copilot, Claude

---

# ES VERSION

`UpdateAppsDrivers8.1.ps1` actualiza automáticamente aplicaciones, apps de Microsoft Store, drivers y Windows, y puede programarse solo como tarea semanal.

## Requisitos

- Windows 10/11 o Windows Server 2019+ (con Desktop Experience). Basta Windows PowerShell 5.1 para empezar: el script se relanza en PowerShell 7 y lo instala si falta.
- Conexión a Internet.
- Permisos de administrador para Windows Update, instalar PowerShell 7/WinGet y crear la tarea programada.

## Qué hace

La ejecución se organiza en cuatro pasos numerados:

1. **RuckZuck (RZGet)** – revisa por separado los ámbitos *máquina* y *usuario* y actualiza cada app una por una.
2. **WinGet** – muestra los pendientes en una tabla y actualiza paquete por paquete (un fallo no bloquea al resto). Instala WinGet automáticamente si falta (incluye LTSC/Server).
3. **Microsoft Store** – `wsreset` + `winget upgrade --source msstore`. Se omite en Windows Server y en ejecuciones programadas.
4. **Windows Update** – parches y drivers mediante el módulo `PSWindowsUpdate`.

Al final imprime un resumen (correctos / omitidos / con problemas / reinicio pendiente) y termina con código `1` si algo falló, de modo que el Programador de tareas muestra el estado real.

## Uso

```powershell
# Ejecución interactiva (pregunta una vez si crear la tarea semanal)
.\UpdateAppsDrivers8.1.ps1

# Solo listar lo pendiente, sin instalar nada
.\UpdateAppsDrivers8.1.ps1 -DryRun

# No preguntar por la tarea programada
.\UpdateAppsDrivers8.1.ps1 -SkipScheduleTask
```

## Parámetros

| Parámetro | Descripción |
|---|---|
| `-DryRun` | Solo lista las actualizaciones pendientes; no instala nada. |
| `-SkipScheduleTask` | Nunca pregunta por la tarea programada. |
| `-ReconfigureTask` | Cambia día/hora de una tarea existente (por defecto no se vuelve a preguntar). |
| `-ScheduledRun` | Uso de la tarea programada: sin preguntas, instala WinGet si falta. |
| `-SkipStore` | Omite los pasos de Microsoft Store. |
| `-IncludePinned` | Actualiza también paquetes WinGet anclados (por defecto se respetan). |
| `-IncludeUnknown` | Incluye paquetes WinGet de versión desconocida (por defecto se omiten). |
| `-AllowReinstall` | Permite desinstalar + reinstalar cuando WinGet indica otra tecnología de instalación (desactivado por defecto). |
| `-ExcludeIds` | Ids de WinGet a omitir, separados por comas. También se lee `exclusiones.txt` (un Id por línea, `#` para comentarios) junto al script. |
| `-RebootPolicy` | `None` (por defecto, solo avisa) o `IfPending` (reinicia a los 60 s si hay reinicio pendiente). |
| `-LogRetentionDays` | Días que se conservan los `Logs\Actualizar-*.log` (por defecto 30). |
| `-ForceWinGetReinstall` | Reinstala WinGet aunque ya esté disponible. |
| `-NoRelaunch` | No relanzar en PowerShell 7. |
| `-OutputFolder` | Carpeta de descargas y de la subcarpeta `Logs` (por defecto, la del script). |

## Tarea programada

En la primera ejecución interactiva el script ofrece crear una tarea semanal (`UpdateAppsDrivers8.1-<hash>`) que corre como SYSTEM el día y la hora que elija. Funciona con batería, solo si hay red y tiene un límite de 4 horas. Una vez creada no vuelve a preguntar; use `-ReconfigureTask` para modificarla. Conserve el script en la misma ruta a la que apunta la tarea.

## Logs y seguridad

- Los transcripts y el log de recuperación manual se guardan en `Logs\` junto al script y se rotan por antigüedad.
- Los instaladores descargados (MSI de PowerShell 7, VC++ redistributable, bundle de WinGet) deben tener firma válida de Microsoft; `RZGet.exe` se verifica y solo avisa.
- Los paquetes que el editor no permite actualizar con WinGet (p. ej. Android Studio) se reportan como *omitidos*, no como fallos.

## Pruebas

```powershell
pwsh -NoProfile -File tests/ScheduledTask.Tests.ps1
pwsh -NoProfile -File tests/WinGetContinuation.Tests.ps1
pwsh -NoProfile -File tests/WinGetRecovery.Tests.ps1
```

Extraen funciones del script y simulan cmdlets; no actualizan nada ni registran tareas reales.

## Créditos

- **Autor:** Daniel Landivar – danny9001@gmail.com
- **Licencia:** CC BY-NC (Reconocimiento-NoComercial)
- **Editor:** Microsoft Copilot, Claude
