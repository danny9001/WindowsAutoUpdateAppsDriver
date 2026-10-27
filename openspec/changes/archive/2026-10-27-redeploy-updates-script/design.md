# Diseno

Paso de preparacion remoto: si la tarea existe, se acepta solo si `Description` es 'Ejecucion puntual del actualizador GenIT', alguna accion tiene en `Arguments` la ruta citada del script destino y `State` no es Running. Devuelve `Reuse`.

Paso de instalacion: vuelve a validar lo mismo (la tarea pudo cambiar entre pasos). Con `Reuse` copia el script con respaldo y no registra la tarea; el resultado tiene Estado 'Actualizado'. Sin tarea, el flujo no cambia.

Pruebas en `tests/RemoteDeployment.Tests.ps1`: segundo despliegue con la misma fecha queda 'Actualizado', respalda el script y no registra otra tarea; tarea ajena con ese nombre y tarea en ejecucion siguen siendo error.
