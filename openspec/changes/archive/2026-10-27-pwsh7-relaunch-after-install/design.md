# Diseno

`Find-PwshPath`: recarga el PATH del proceso desde el registro (Machine y User) y busca pwsh.exe con `Get-Command`; si no aparece, prueba `%ProgramW6432%` y `%ProgramFiles%\PowerShell\7\pwsh.exe` (ProgramW6432 cubre un proceso de 32 bits). Devuelve la ruta o `$null`.

`Install-PowerShell7`: revisa el codigo de msiexec (0, 1641 y 3010 son correctos; otro es fallo) y verifica con `Find-PwshPath`.

`Ensure-PowerShell7`: usa `Find-PwshPath` y `Get-PwshRelaunchArguments` (argumentos sin comillas incrustadas; el operador `&` cita los que tienen espacios). Relanza con `& $pwsh @args` en la misma consola y termina con `exit $LASTEXITCODE`. Si el relanzamiento no arranca, avisa y devuelve `$false`.

Flujo principal: si tras instalar no se puede relanzar, avisa que continua en 5.1.

Pruebas: `tests/PowerShell7Relaunch.Tests.ps1` comprueba que `Find-PwshPath` encuentra pwsh con un PATH sin su carpeta y que los argumentos llegan intactos (rutas con espacios, ExcludeIds, switches) a un script de prueba, tambien desde Windows PowerShell 5.1.
