# Configuracion de UpdateAppsDrivers8.1

El script lee `UpdateAppsDrivers8.1.config.json` en su misma carpeta antes de ejecutar actualizaciones. Si falta, lo crea con los valores de `UpdateAppsDrivers8.1.config.example.json`. No necesita parametros. JSON invalido detiene el proceso y muestra el motivo.

```json
{
  "AskQuestions": false,
  "SkipStore": true,
  "SkipPackages": ["Microsoft.SQLServer.OLEDBDriver"],
  "InstallWinGetIfMissing": true,
  "Schedule": {
    "Enabled": true,
    "DayOfWeek": "Friday",
    "Time": "22:30"
  }
}
```

- `AskQuestions: false`: no pregunta por tarea, instalacion WinGet o recuperacion de paquetes fallidos. Los fallos se registran para recuperacion manual.
- `SkipStore`: omite Microsoft Store. Server ya la omite automaticamente.
- `SkipPackages`: IDs exactos omitidos por el actualizador WinGet. Se combina con `-ExcludeIds` y `exclusiones.txt` de la version actual. No controla RuckZuck, Windows Update ni dependencias que otro instalador pueda requerir. Para volver a intentar un paquete, quitarlo de las listas de exclusion.
- `InstallWinGetIfMissing`: permite instalar WinGet si falta, tambien en ejecuciones programadas.
- `RuckZuck.SkipShortNames`: lista de nombres cortos propios de RuckZuck; no son los IDs WinGet. Ejemplo: `"SkipShortNames": ["Firefox"]`. Una exclusion de WinGet no excluye automaticamente la misma aplicacion en RuckZuck ni sus dependencias.
- `RuckZuck.DelayDays`: edad minima de actualizaciones detectadas, de 0 a 365 dias; 0 mantiene el comportamiento anterior. No se aplica a la comprobacion posterior.
- `RuckZuck.ScanTimeoutSeconds`: limite por consulta, 10 a 3600 segundos (180 por defecto).
- `RuckZuck.InstallTimeoutSeconds`: limite por instalacion, 30 a 14400 segundos (1800 por defecto). Al agotarlo se detiene RZGet y se interrumpen sus siguientes paquetes; Windows Installer podria seguir activo.
- `RuckZuck.VersionCheckDays`: frecuencia de consulta de la ultima version, de 1 a 90 dias (7 por defecto). Se compara SHA-256 con el digest de la release de GitHub antes de reemplazar RZGet. Si falla la consulta se conserva la copia anterior con aviso. `RZGet.exe` y `RZGet.exe.config` se reemplazan juntos: si falla uno se restauran ambos anteriores, y un reemplazo interrumpido se recupera en la siguiente ejecucion.
- `Schedule.Enabled: true`: crea o actualiza la tarea de esta copia del script sin preguntas. Usa SYSTEM y requiere administrador. Valores de dia: Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday. Hora local en formato HH:mm.
- `Schedule.Enabled: false`: no crea/actualiza tareas. No elimina ni desactiva una tarea que ya exista; puede desactivarse desde el Programador de tareas.

Para usar una vez el menu de programacion, poner `AskQuestions: true` y `Schedule.Enabled: false`. Al rechazar la tarea o guardar el horario, AskQuestions vuelve a false y se guarda la decision. Para usar el menu de recuperacion manual, activar AskQuestions con un horario ya configurado. Elegir 3 (omitir paquete) agrega su ID a SkipPackages; elegir 2 guarda el comando sin excluirlo.

La tarea usa el mismo archivo JSON junto al script. Conservar ambos en esa carpeta, con permiso de lectura para SYSTEM. El archivo local no se versiona para conservar las decisiones de cada equipo. Las pruebas son simuladas; no registran tareas reales ni instalan programas.

Integrado sobre la version 704afce del repositorio: conserva sus correcciones de RuckZuck, presentacion, firmas y opciones de actualizacion. Los registros de recuperacion se guardan en la carpeta `Logs` de OutputFolder. DryRun no crea el JSON si falta.

Los cambios de RuckZuck son opcionales: archivos JSON anteriores siguen siendo validos y usan los valores predeterminados. Para personalizarlos, agregue el objeto `RuckZuck` del archivo de ejemplo a su JSON existente. Los registros completos de cada consulta e instalacion quedan en `Logs\RuckZuck`. Un codigo 0 no basta para confirmar exito: se exige el mensaje de instalacion y que una consulta posterior no liste el paquete. Una lista vacia de RZGet solo significa que no se detectaron pendientes; el propio cliente puede ocultar algunos errores de consulta.
