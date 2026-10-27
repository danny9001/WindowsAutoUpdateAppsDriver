# Volver a desplegar actualiza el script

Al repetir `Deploy-UpdateAppsDriversRemote.ps1` con la misma fecha, la tarea `GenIT-UpdateAppsDrivers-Once-<fecha>` ya existe y el despliegue falla antes de copiar: el equipo se queda con la copia anterior del actualizador y la tarea la ejecuta igual. Paso el 2026-10-27 en 5 de 6 servidores, que siguieron con la version previa al arreglo de PowerShell 7.

Si la tarea existente es de este despliegue (misma descripcion y accion sobre el mismo script) y no se esta ejecutando, actualizar el script (respaldo y SHA-256) y conservar la tarea. Una tarea ajena con ese nombre o una ejecucion en curso siguen siendo error.
