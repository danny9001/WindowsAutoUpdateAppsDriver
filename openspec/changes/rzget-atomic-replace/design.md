# Diseno

Separar el reemplazo en una funcion propia (Install-RZGetFiles) probable sin red. Para cada archivo preparado y verificado: renombrar el actual a un respaldo `.bak` con GUID y mover el nuevo a su lugar. Si cualquier paso falla (archivo bloqueado por un RZGet en ejecucion, permisos, disco), quitar los nuevos ya colocados, devolver los respaldos a su nombre y relanzar el error; la funcion que llama conserva el par anterior con aviso. Con exito, borrar los respaldos.

Windows no ofrece un reemplazo atomico de dos archivos sin NTFS transaccional (obsoleto); renombrar dentro de la misma carpeta es rapido y reversible, y la reversion cubre fallas controladas. Para una interrupcion abrupta (corte de energia, proceso detenido) entre renombre y movimiento, al inicio de Download-RZGet se restaura el respaldo mas reciente de un archivo que falte y se eliminan respaldos y descargas huerfanos, solo con el patron `<archivo>.<guid32>.bak|download` para no tocar otros archivos.

La firma Authenticode del ejecutable se revisa antes de reemplazar, como antes. Sin cambios en la configuracion JSON ni en DryRun.

Validar con archivos temporales: reemplazo exitoso, falla del segundo archivo con reversion completa, recuperacion de un reemplazo interrumpido y limpieza de huerfanos; mas las pruebas existentes.
