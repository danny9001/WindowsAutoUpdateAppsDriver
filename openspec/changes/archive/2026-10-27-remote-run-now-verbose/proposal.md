# Ejecucion inmediata, detallada y recoleccion de logs

El usuario pidio (2026-10-27) ejecutar el actualizador a la vez en todos los servidores, en modo detallado, para revisar su funcionamiento. Hoy el despliegue solo programa una fecha, no pasa `-Verbose` y los logs quedan en cada servidor.

- `-RunNow`: registra una tarea `GenIT-UpdateAppsDrivers-Now-<fecha-hora>` sin disparador (SYSTEM) y la inicia en cada destino; todos corren en paralelo.
- `-UpdaterVerbose`: agrega `-Verbose` a la tarea (programada o inmediata).
- `-CollectLogs`: copia los `Actualizar-*.log` recientes de cada destino a `Logs\Remote\<equipo>` junto al despliegue e informa el estado de las tareas GenIT.
- El actualizador no admite dos ejecuciones simultaneas en el mismo equipo (mutex global), por ejemplo la inmediata y la de las 23:00.
