# Modo detallado para analisis y correccion

Hoy, cuando algo falla, el resumen muestra el codigo y un log, pero no los comandos exactos ejecutados, sus tiempos ni el contexto del equipo. Diagnosticar el 9009 de HP Image Assistant exigio reproducir a mano el install.cmd y descubrir una variable de entorno.

Agregar un modo detallado, activable con `-Verbose` o con `"Verbose": true` en el JSON (para la tarea programada), que registre el contexto del equipo al inicio y cada comando externo con sus argumentos, codigo de salida y duracion, listo para copiar y reproducir. Todo queda tambien en el transcript de Logs.
