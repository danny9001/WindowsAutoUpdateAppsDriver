# Verificacion

PASS con PowerShell 7: parseo del script, rechazo de crear tarea, entradas invalidas de dia/hora, registro semanal lunes 22:30, principal SYSTEM, IgnoreNew, argumentos NonInteractive/ScheduledRun/SkipStore, rechazo de reemplazar tarea existente, bootstrap WinGet sin preguntas en ScheduledRun.

Se simularon los cmdlets de tareas; no se registro ninguna tarea real ni se ejecutaron actualizaciones o instaladores. Falta validacion real en Windows Server 2022 GUI. Las tareas usan el huso horario local del equipo; el script debe conservarse en su ruta original.

Se corrigio el paso de parametros al relanzar en PS7 para conservar SkipStore, ForceWinGetReinstall y ScheduledRun. La tarea no repite ForceWinGetReinstall cada semana.
