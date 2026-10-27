# Diseno

Criterio: un archivo sigue activo si UpdateAppsDrivers8.1, sus pruebas o el README lo usan. Ninguna tarea programada del equipo apunta a los archivos que se mueven (revisado con Get-ScheduledTask).

Se archivan con `git mv` (el historial se conserva con `git log --follow`):

- UpdateAppsDrivers7.1.ps1, UpdateAppsDrivers7.2.ps1, UpdateAppsDrivers8.ps1 y UpdateAppsDriversSilence.ps1: versiones anteriores reemplazadas por 8.1.
- CreateTask.ps1: programa UpdateAppsDrivers3.ps1, que ya no existe; 8.1 crea su propia tarea semanal.
- Reinstalar-WinGet.ps1: 8.1 instala WinGet si falta y admite -ForceWinGetReinstall.
- Advanced-DriverDownloader.ps1 y Advanced-DriverDownloaderPS7.ps1: descargador de drivers independiente, sin referencias en 8.1 ni en el README; 8.1 actualiza drivers con Windows Update.

Los changes OpenSpec completos pasan a `openspec/changes/archive/<fecha>-<nombre>/`, con la fecha de su commit, segun la convencion de OpenSpec. La tarea pendiente de schedule-updater (vincular en MemAI) no puede cumplirse: MemAI solo vincula changes del OpenSpec del servidor. Se marca como no aplicable.

Archivos locales no versionados del actualizador:

- UpdateAppsDriversSilence2.ps1, Winget.ps1 (copias identicas de archivos archivados) y Universal-DriverUpdater.ps1 (otro actualizador de drivers): pasan a `archive/local/`, que se excluye en .gitignore.
- Actualizar-*.log y WinGet-Recuperacion-manual.log de la raiz (de antes de que 8.1 usara `Logs\`): pasan a `Logs\`, donde la rotacion por antiguedad los gestiona.

Fuera de alcance: los demas scripts de C:\Script (Intune, GPO, respaldo, etc.) y RuckZuck.exe, que no forman parte de este repositorio.

Se actualiza el README (carpeta archive y lista completa de pruebas). Validar ejecutando todas las pruebas despues de mover.
