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
- `Schedule.Enabled: true`: crea o actualiza la tarea de esta copia del script sin preguntas. Usa SYSTEM y requiere administrador. Valores de dia: Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday. Hora local en formato HH:mm.
- `Schedule.Enabled: false`: no crea/actualiza tareas. No elimina ni desactiva una tarea que ya exista; puede desactivarse desde el Programador de tareas.

Para usar una vez el menu de programacion, poner `AskQuestions: true` y `Schedule.Enabled: false`. Al rechazar la tarea o guardar el horario, AskQuestions vuelve a false y se guarda la decision. Para usar el menu de recuperacion manual, activar AskQuestions con un horario ya configurado. Elegir 3 (omitir paquete) agrega su ID a SkipPackages; elegir 2 guarda el comando sin excluirlo.

La tarea usa el mismo archivo JSON junto al script. Conservar ambos en esa carpeta, con permiso de lectura para SYSTEM. El archivo local no se versiona para conservar las decisiones de cada equipo. Las pruebas son simuladas; no registran tareas reales ni instalan programas.

Integrado sobre la version 704afce del repositorio: conserva sus correcciones de RuckZuck, presentacion, firmas y opciones de actualizacion. Los registros de recuperacion se guardan en la carpeta `Logs` de OutputFolder. DryRun no crea el JSON si falta.
