# Diseno

Activacion: el parametro comun `-Verbose` (el script ya tiene CmdletBinding) o `Verbose: true` en el JSON. La tarea programada lee el JSON en cada ejecucion, asi que no hace falta cambiar sus argumentos. Al relanzarse en PowerShell 7 se reenvia `-Verbose`.

La salida usa una funcion propia, Write-Diag, con hora y prefijo `[diag]`, escrita con Write-Host para que quede en el transcript. El `-Verbose` nativo de PowerShell se desactiva dentro del script: haria que Import-Module, Get-CimInstance, Expand-Archive y otros cmdlets llenen la salida de mensajes internos sin valor para el diagnostico.

Contexto al inicio: ruta y SHA-256 del script (identifica la version exacta en cada equipo), PowerShell y edicion, Windows y build, servidor o cliente, usuario (SYSTEM en la tarea), modo, carpeta de salida, JSON efectivo, fabricante y modelo, proxy del sistema, politica de ejecucion, NoDefaultCurrentDirectoryInExePath y causas de reinicio pendiente.

Puntos instrumentados (los ayudantes centrales, para cubrir todo sin tocar cada llamada): Invoke-RuckZuckProcess, Invoke-DriverProcess, Invoke-WinGet e Invoke-WindowsPowerShellCommand registran la linea de comandos, el codigo de salida y la duracion; Invoke-Download registra URL, destino y tamano; Get-PendingReboot registra que clave indica el reinicio; el cruce de Intel registra cada dispositivo coincidente y la comparacion de versiones; la migracion de tareas registra las acciones revisadas; Test-Internet muestra las sondas fallidas.

Sin modo detallado la salida no cambia. Validar con pruebas: activacion por parametro y por JSON, rechazo de valor no booleano, formato de Write-Diag, registro de comandos con codigo y duracion, y silencio cuando esta desactivado.
