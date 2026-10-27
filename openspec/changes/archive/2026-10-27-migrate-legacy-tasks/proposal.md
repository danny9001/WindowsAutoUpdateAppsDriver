# Migrar tareas programadas de versiones anteriores

El script esta instalado en varios servidores y equipos, con tareas semanales que ejecutan versiones anteriores (por ejemplo DailyUpdateAppsDrivers, que CreateTask.ps1 creaba hacia UpdateAppsDrivers3.ps1, o tareas creadas a mano hacia 7.x u 8). La 8.1 solo gestiona su propia tarea, asi que un equipo puede quedar con dos tareas o seguir ejecutando el script viejo.

Cuando la 8.1 se ejecute en un equipo (la copia la hace el administrador, como hasta ahora), detectara las tareas que ejecutan una version anterior, creara su propia tarea conservando el dia y la hora, verificara que existe y eliminara las tareas anteriores. Sin autoactualizacion ni distribucion automatica.
