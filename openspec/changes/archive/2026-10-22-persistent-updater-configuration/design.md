# Diseno

Base actualizada a origin/main 704afce (reorganizacion de salida y correcciones RuckZuck). Integrar SkipPackages en Get-ExcludedIds para conservar tambien ExcludeIds y exclusiones.txt. Conservar DryRun, politicas de reinicio, validacion de firmas, resumen y retencion de logs de esa version. DryRun no crea el JSON predeterminado si falta. Las opciones nuevas de seguridad y actualizacion de la base se mantienen.

Funciones Initialize/Save-UpdaterConfiguration. Valores tipados, validacion de dias, horas e IDs. Config local excluida de Git y ejemplo versionado. El script guarda decisiones con JSON y escritura temporal/Move-Item. SkipStore explicito sigue teniendo prioridad para omitir Store.

Schedule.Enabled true registra/actualiza la tarea con DayOfWeek/Time sin menu; false evita la pregunta salvo AskQuestions=true. Preguntas se desactivan siempre en ScheduledRun. SkipPackages se aplica a la actualizacion WinGet por ID y a reinstalaciones; no afecta RuckZuck/Windows Update. Si hay exclusiones se evita fallback upgrade --all para no ignorarlas. La accion programada lee el mismo config junto al archivo.

Pruebas con JSON temporal y cmdlets simulados para valores predeterminados, persistencia, validacion, exclusion, modo sin preguntas y horario configurado. No ejecutar instaladores ni tareas reales. MemAI no disponible en esta sesion.
