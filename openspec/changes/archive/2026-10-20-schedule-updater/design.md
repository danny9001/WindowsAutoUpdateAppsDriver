# Diseno

Agregar Configure-UpdaterScheduledTask despues del bootstrap de PowerShell y antes del flujo de actualizacion. Crear un trigger semanal, principal SYSTEM ServiceAccount Highest, StartWhenAvailable y MultipleInstances IgnoreNew.

La accion usa una ruta absoluta a pwsh.exe y al script, directorio de trabajo explicito y OutputFolder. El parametro interno ScheduledRun evita las preguntas en ejecuciones automaticas y autoriza el bootstrap de WinGet que el administrador acepta al programar.

El nombre incluye SHA256 de la ruta del script para distinguir instalaciones. Una tarea existente requiere confirmacion antes de reemplazarse. Validar entradas con expresiones regulares antes de convertirlas.

Pruebas con funciones extraidas del AST y cmdlets simulados: rechazar crear, validar entradas invalidas, registrar dia/hora y accion, no reemplazar sin confirmar, no preguntar en ScheduledRun. No ejecutar actualizaciones ni crear una tarea real en el equipo de desarrollo.
