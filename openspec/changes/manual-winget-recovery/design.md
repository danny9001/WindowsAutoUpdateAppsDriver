# Diseno

Agregar Resolve-WinGetFailure para registrar ID, codigo/detalle y comando exacto en un archivo de recuperacion del OutputFolder. Menus 1=reintento --interactive --exact, 2=comando, 3=omitir. Un unico reintento por fallo; ante error continuar. Invocar desde errores de upgrade, reinstalacion y excepciones. ScheduledRun omite el menu. Usar Invoke-WinGet para mantener resolucion de ejecutable en Server.

Validar con cmdlets simulados las tres opciones, fallo de reintento y ausencia de preguntas en ScheduledRun; conservar pruebas de continuidad y programacion. MemAI no disponible en esta sesion.
