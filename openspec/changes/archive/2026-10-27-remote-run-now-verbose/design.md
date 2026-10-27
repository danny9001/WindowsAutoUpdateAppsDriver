# Diseno

Actualizador: `Global\GenIT-UpdateAppsDrivers8.1` se toma justo antes del flujo de actualizacion, despues del relanzamiento en pwsh (si lo tomara el proceso 5.1, el pwsh hijo no podria). Un mutex abandonado cuenta como tomado. Si otra ejecucion lo tiene: aviso, fin del transcript y `exit 2`. Se libera al terminar.

Despliegue, `-RunNow` (excluye `-UpdateAt`): nombre `GenIT-UpdateAppsDrivers-Now-yyyyMMdd-HHmmss`, sin comprobaciones de fecha, `Register-ScheduledTask` sin `-Trigger` y, despues de actualizar las copias existentes, `Start-ScheduledTask`. Estado `Iniciado`.

`-CollectLogs` (sin fecha ni copia): por destino, `Get-ScheduledTask` de `GenIT-UpdateAppsDrivers-*` con `Get-ScheduledTaskInfo` (estado, ultima ejecucion, resultado) y lista de `Logs\Actualizar-*.log` de las ultimas `-LogHours` (24); `Copy-Item -FromSession` a `-LocalLogFolder` (`Logs\Remote\<equipo>`). El transcript en curso se puede copiar mientras se escribe.

Pruebas: `tests/RemoteDeployment.Tests.ps1` (RunNow sin disparador, inicio, -Verbose en argumentos, CollectLogs con sesiones simuladas) y `tests/SingleInstance.Tests.ps1` (segundo proceso real termina con 2).
