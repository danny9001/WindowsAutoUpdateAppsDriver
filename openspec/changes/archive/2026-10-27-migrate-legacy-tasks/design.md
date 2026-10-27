# Diseno

Tarea antigua: su nombre es DailyUpdateAppsDrivers, o alguna de sus acciones ejecuta un archivo UpdateAppsDrivers*.ps1 que no es UpdateAppsDrivers8.1.ps1 (3, 7.1, 7.2, 8, Silence, etc.). Las tareas UpdateAppsDrivers8.1-<hash> de otras copias de la 8.1 no se tocan.

Horario de la nueva tarea:
- Si ya existe la tarea de esta copia de la 8.1, se conserva su horario y solo se eliminan las anteriores.
- Si la tarea antigua es semanal con un solo dia, se usan ese dia y esa hora.
- Si es diaria u otro caso, se usa su hora con el dia de Schedule.DayOfWeek del JSON (domingo por defecto), porque el uso acordado es semanal.
- Sin hora legible, se usa el horario del JSON.

El horario se guarda en el JSON (Schedule.Enabled=true) para que las ejecuciones siguientes lo mantengan. La creacion reutiliza el mismo registro de tarea de la 8.1 (SYSTEM, PowerShell 7, semanal), extraido a Register-UpdaterScheduledTask. La tarea antigua solo se elimina despues de comprobar que la nueva existe; si algo falla, la antigua queda intacta y se informa.

Se ejecuta antes de las actualizaciones, como administrador, tambien en ejecuciones programadas. En DryRun solo lista lo que haria. Los scripts antiguos no se borran: solo sus tareas.

Validar con tareas simuladas: deteccion por nombre y por accion, exclusion de otras copias 8.1, horario semanal y diario, tarea 8.1 ya existente, falla al crear (la antigua no se borra) y DryRun.
