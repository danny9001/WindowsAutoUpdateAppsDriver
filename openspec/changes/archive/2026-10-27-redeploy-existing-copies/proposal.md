# El despliegue actualiza tambien las copias existentes

`Deploy-UpdateAppsDriversRemote.ps1` copia el actualizador a `C:\ProgramData\GenIT\UpdateAppsDrivers`, pero los equipos ya tienen copias en otras carpetas (por ejemplo `C:\Medios` en LPZVMAD01) que sus tareas recurrentes ejecutan cada semana. Esas copias quedan desactualizadas.

En cada destino, buscar las tareas programadas cuya accion ejecuta `UpdateAppsDrivers8.1.ps1` y actualizar ese archivo en su propia carpeta, con respaldo y SHA-256, conservando su JSON y la tarea. Decision del usuario (2026-10-27): "que actualice tambien las copias en otras carpetas".
