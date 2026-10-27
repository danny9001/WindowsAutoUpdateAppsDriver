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
- `Verbose`: modo detallado para analisis y correccion (false por defecto); equivale a ejecutar con `-Verbose`. Muestra al inicio el contexto del equipo (ruta y SHA-256 del script, PowerShell, Windows, fabricante y modelo, usuario, JSON efectivo, proxy, politica de ejecucion, `NoDefaultCurrentDirectoryInExePath` y causa de reinicio pendiente) y registra cada comando externo con sus argumentos, codigo de salida y duracion, listo para copiar y reproducir; tambien las descargas, la comparacion de versiones de Intel y la revision de tareas anteriores. Las lineas `[diag]` quedan en el transcript de `Logs`. Util en la tarea programada: se activa en el JSON sin cambiar la tarea.
- `RuckZuck.SkipShortNames`: lista de nombres cortos propios de RuckZuck; no son los IDs WinGet. Ejemplo: `"SkipShortNames": ["Firefox"]`. Una exclusion de WinGet no excluye automaticamente la misma aplicacion en RuckZuck ni sus dependencias.
- `RuckZuck.DelayDays`: edad minima de actualizaciones detectadas, de 0 a 365 dias; 0 mantiene el comportamiento anterior. No se aplica a la comprobacion posterior.
- `RuckZuck.ScanTimeoutSeconds`: limite por consulta, 10 a 3600 segundos (180 por defecto).
- `RuckZuck.InstallTimeoutSeconds`: limite por instalacion, 30 a 14400 segundos (1800 por defecto). Al agotarlo se detiene RZGet y se interrumpen sus siguientes paquetes; Windows Installer podria seguir activo.
- `RuckZuck.VersionCheckDays`: frecuencia de consulta de la ultima version, de 1 a 90 dias (7 por defecto). Se compara SHA-256 con el digest de la release de GitHub antes de reemplazar RZGet. Si falla la consulta se conserva la copia anterior con aviso. `RZGet.exe` y `RZGet.exe.config` se reemplazan juntos: si falla uno se restauran ambos anteriores, y un reemplazo interrumpido se recupera en la siguiente ejecucion.
- `Drivers.Sources`: fuentes de drivers en orden; por defecto `["Oem", "Intel", "WindowsUpdate"]`. `Oem` usa la herramienta oficial del fabricante del equipo (HP Image Assistant, Dell Command | Update o el modulo LSUClient de Lenovo), que detecta lo que aplica al modelo. `Intel` usa el catalogo publico de Intel Driver & Support Assistant e instala solo si la version del driver supera la instalada. Sin `WindowsUpdate`, Windows Update solo aplica parches del sistema.
- `Drivers.IncludeFirmware`: incluye BIOS y firmware del fabricante del equipo (true por defecto). Solo con el equipo conectado a la corriente; antes se suspende BitLocker hasta el siguiente reinicio. El script nunca reinicia por su cuenta: respeta `-RebootPolicy`.
- `Drivers.InstallVendorTool`: permite descargar la herramienta del fabricante si falta (HP Image Assistant se extrae en `Drivers\HPIA`, sin instalarse).
- `Drivers.SkipIntelIds`: IDs de paquetes del catalogo de Intel que no se instalan (aparecen en la URL de descarga de Intel).
- `Drivers.InstallTimeoutSeconds`: limite por herramienta o instalador, 60 a 14400 segundos (3600 por defecto).
- `Schedule.Enabled: true`: crea o actualiza la tarea de esta copia del script sin preguntas. Usa SYSTEM y requiere administrador. Valores de dia: Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday. Hora local en formato HH:mm.
- Tareas de versiones anteriores: en cada ejecucion como administrador, el script busca tareas que ejecutan una version anterior (`DailyUpdateAppsDrivers` de CreateTask.ps1, o acciones hacia `UpdateAppsDrivers3/7.x/8/Silence.ps1`). Si esta copia aun no tiene tarea, la crea con el mismo dia y hora (si la anterior era diaria, con su hora y el dia de `Schedule.DayOfWeek`) y guarda ese horario en el JSON. Despues de comprobar que la nueva existe, elimina las anteriores. Si algo falla, las anteriores se conservan. Los scripts antiguos no se borran; las tareas de otras copias de la 8.1 no se tocan. DryRun solo informa.
- `Schedule.Enabled: false`: no crea/actualiza tareas. No elimina ni desactiva una tarea que ya exista; puede desactivarse desde el Programador de tareas.

Para usar una vez el menu de programacion, poner `AskQuestions: true` y `Schedule.Enabled: false`. Al rechazar la tarea o guardar el horario, AskQuestions vuelve a false y se guarda la decision. Para usar el menu de recuperacion manual, activar AskQuestions con un horario ya configurado. Elegir 3 (omitir paquete) agrega su ID a SkipPackages; elegir 2 guarda el comando sin excluirlo.

La tarea usa el mismo archivo JSON junto al script. Conservar ambos en esa carpeta, con permiso de lectura para SYSTEM. El archivo local no se versiona para conservar las decisiones de cada equipo. Las pruebas son simuladas; no registran tareas reales ni instalan programas.

Integrado sobre la version 704afce del repositorio: conserva sus correcciones de RuckZuck, presentacion, firmas y opciones de actualizacion. Los registros de recuperacion se guardan en la carpeta `Logs` de OutputFolder. DryRun no crea el JSON si falta.

Los cambios de RuckZuck son opcionales: archivos JSON anteriores siguen siendo validos y usan los valores predeterminados. Para personalizarlos, agregue el objeto `RuckZuck` del archivo de ejemplo a su JSON existente. Los registros completos de cada consulta e instalacion quedan en `Logs\RuckZuck`. Un codigo 0 no basta para confirmar exito: se exige el mensaje de instalacion y que una consulta posterior no liste el paquete. Una lista vacia de RZGet solo significa que no se detectaron pendientes; el propio cliente puede ocultar algunos errores de consulta.

Drivers de Intel: cada paquete se descarga de downloadmirror.intel.com, se compara con el SHA-1 del catalogo y debe tener firma valida de Intel Corporation. Se instala en silencio con las opciones documentadas por Intel (graficos `-s`; Wi-Fi y Bluetooth `/quiet /norestart`). El exito se confirma solo si el driver del dispositivo alcanza la version del catalogo. Los paquetes sin modo silencioso verificado se informan con su enlace. Los dispositivos sin driver se listan con su nombre de pci.ids. Los reportes de HP Image Assistant y Dell quedan en `Logs`.
