# Programar el actualizador 8.1

Ofrecer al ejecutar el script una pregunta opcional para crear una tarea semanal con dia y hora elegidos por el administrador. Conservar el proceso de actualizacion de 7.1 y los instaladores de PowerShell/WinGet de 8.1.

## Requisitos
- Preguntar S/N y validar dia 1-7 y hora HH:mm.
- No crear tareas si se responde N o faltan privilegios.
- Ejecutar el archivo actual con PowerShell 7, como SYSTEM, aun sin sesion abierta.
- La tarea no debe preguntar por su propia creacion ni por la instalacion de WinGet.
- Solicitar confirmacion antes de reemplazar una tarea existente.
- Usar el horario local del equipo y evitar ejecuciones simultaneas.

## Limites
MemAI no esta disponible en esta sesion; vinculacion y archivado remoto pendientes. No se garantiza que las aplicaciones por usuario o Microsoft Store funcionen bajo SYSTEM.
