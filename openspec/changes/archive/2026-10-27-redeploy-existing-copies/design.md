# Diseno

Descubrimiento (en el destino): `Get-ScheduledTask` sin nombre; de `Execute + Arguments` de cada accion se toma la ruta que sigue a `-File` (con o sin comillas) y termina en `\UpdateAppsDrivers8.1.ps1`. Si no es absoluta se combina con `WorkingDirectory`. Solo rutas locales (`X:\...`), existentes, distintas del destino del despliegue y sin repetir. Se guarda que tareas usan cada ruta.

Actualizacion (despues de instalar y verificar la copia principal): por cada ruta,
- si alguna tarea que la usa esta Running, no se toca (error de esa copia);
- si su SHA-256 ya es el esperado, queda "al dia" sin respaldo;
- si no: copia local desde la principal a `<ruta>.<guid>.staging`, verifica SHA-256, respaldo `.backup-<fecha>-<guid>` y `Move-Item -Force`. Si falla, se borra el staging.
El JSON de esa carpeta y la tarea no se modifican. Los errores de una copia no detienen las demas.

Resultado: columna `Copias` con cada ruta y su estado (actualizada, al dia, error). Si alguna copia falla, el Estado del equipo es `Parcial` y el script termina con codigo 1.

Pruebas en `tests/RemoteDeployment.Tests.ps1` con tareas simuladas: copia con comillas y sin comillas, ruta relativa con WorkingDirectory, copia al dia, tarea en ejecucion, ruta inexistente, ruta UNC ignorada, otra version (7.1) ignorada y JSON intacto.
