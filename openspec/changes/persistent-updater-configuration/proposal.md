# Configuracion persistente 8.1

Leer UpdateAppsDrivers8.1.config.json junto al script en cada ejecucion. Si falta, crear valores predeterminados sin preguntas: no programar tareas, instalar WinGet si falta, registrar fallos para recuperacion manual y no omitir paquetes.

Permitir configurar preguntas interactivas, Store, paquetes omitidos, instalacion WinGet y tarea semanal. En modo interactivo recordar rechazo de programacion, horario creado y paquetes omitidos. ScheduledRun nunca pregunta. JSON invalido debe detener la ejecucion antes de actualizar o registrar tareas.
