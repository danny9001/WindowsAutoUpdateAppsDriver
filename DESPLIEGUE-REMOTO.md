# Despliegue remoto de UpdateAppsDrivers 8.1

Ejecute el instalador desde su equipo con PowerShell y acceso a los destinos por WinRM. `Deploy-UpdateAppsDriversRemote.ps1` y `UpdateAppsDrivers8.1.ps1` deben estar juntos. El destino necesita Windows PowerShell 5.1 y el Programador de tareas; el actualizador intentara instalar PowerShell 7 y WinGet si faltan.

## Uso interactivo

```powershell
cd C:\Script
.\Deploy-UpdateAppsDriversRemote.ps1
```

Escriba nombres DNS separados por comas y una fecha `yyyy-MM-dd HH:mm`. Se solicitara una credencial de dominio con permisos de administrador en los destinos. La contrasena se mantiene en memoria, no se guarda en el archivo ni se registra en la tarea.

## Lista y simulacion

Cree un archivo de texto con un equipo o FQDN por linea; admite lineas comentadas con `#`. Ejemplo: `C:\Script\equipos.txt`.

```powershell
.\Deploy-UpdateAppsDriversRemote.ps1 -ComputerListPath C:\Script\equipos.txt -UpdateAt '2026-11-15 22:00' -WhatIf
```

Para ejecutar sin escribir la lista en un archivo:

```powershell
.\Deploy-UpdateAppsDriversRemote.ps1 -ComputerName PC01,SRV01 -UpdateAt '2026-11-15 22:00'
```

El instalador muestra estado por destino; los errores de un equipo no detienen los demas. `-WhatIf` solo presenta lo que se haria: no verifica conectividad ni pide credenciales.

## Resultado en cada destino

- Copia el actualizador a `C:\ProgramData\GenIT\UpdateAppsDrivers` y verifica el SHA-256. Si ya existia una copia, deja un respaldo con sufijo `.backup-...`.
- Busca las tareas programadas del equipo que ejecutan `UpdateAppsDrivers8.1.ps1` en otra carpeta (por ejemplo la semanal en `C:\Medios`) y actualiza esa copia en su sitio, con respaldo `.backup-...` y SHA-256. No cambia su JSON ni su tarea. Una copia ya al dia no se toca; si su tarea se esta ejecutando o el archivo no existe, se informa y el equipo queda `Parcial`. Solo se consideran rutas locales; las copias sin tarea no se encuentran.
- Conserva `UpdateAppsDrivers8.1.config.json` si ya existe. Si no existe, crea uno sin preguntas ni tarea recurrente y con BIOS/firmware desactivado.
- Registra `GenIT-UpdateAppsDrivers-Once-AAAAMMDD-HHMM` como SYSTEM, para una sola ejecucion en el horario local del destino. Si ya existe esa tarea de un despliegue anterior y no se esta ejecutando, actualiza el script (con respaldo y SHA-256) y conserva la tarea: el resultado dice `Actualizado`. Una tarea ajena con ese nombre o en ejecucion no se toca y se informa como error.
- No inicia actualizaciones al desplegar. La tarea no elimina tareas antiguas del actualizador. Sus resultados se consultan en el Programador de tareas y en `C:\ProgramData\GenIT\UpdateAppsDrivers\Logs`.
- El horario se interpreta en la zona horaria local de cada equipo; el resultado muestra zona y hora observada. Si el equipo esta apagado a esa hora, no se garantiza la ejecucion posterior.
- En tareas SYSTEM, las aplicaciones instaladas solo para perfiles de usuario y Microsoft Store pueden quedar fuera. El instalador no configura WinRM, DNS, firewall, puertos o TrustedHosts.

Si un fallo ocurre despues de copiar, puede quedar un archivo `.staging` o una copia nueva sin tarea: revise la carpeta y el respaldo antes de reintentar. No se usan credenciales de dominio en la tarea. La instalacion es simulada en las pruebas; pruebe primero en un equipo no critico y compruebe el resultado antes de extenderla.

## Ejecucion inmediata y logs

Para iniciar la actualizacion ya, en todos los destinos a la vez y en modo detallado:

```powershell
.\Deploy-UpdateAppsDriversRemote.ps1 -ComputerListPath C:\Script\equipos.txt -RunNow -UpdaterVerbose
```

Registra en cada destino `GenIT-UpdateAppsDrivers-Now-AAAAMMDD-HHMMSS` (SYSTEM, sin disparador), actualiza el script y sus copias como en un despliegue programado e inicia la tarea. `-UpdaterVerbose` tambien sirve con `-UpdateAt`. El actualizador no admite dos ejecuciones a la vez en el mismo equipo: si coincide con otra (por ejemplo, la programada), la segunda termina con codigo 2 sin hacer cambios.

Para revisar el avance o el resultado, en cualquier momento:

```powershell
.\Deploy-UpdateAppsDriversRemote.ps1 -ComputerListPath C:\Script\equipos.txt -CollectLogs
```

Copia los `Actualizar-*.log` de las ultimas 24 horas (`-LogHours`) de cada destino a `C:\Script\Logs\Remote\<equipo>` y muestra el estado de las tareas GenIT (en ejecucion, ultima ejecucion y resultado). Se puede repetir mientras la actualizacion sigue en curso.
