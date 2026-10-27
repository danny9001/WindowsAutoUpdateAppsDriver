# Relanzar en PowerShell 7 tras instalarlo

Al ejecutar el script en Windows PowerShell 5.1 sin PowerShell 7, el script instala el MSI pero sigue en 5.1 y falla por compatibilidad. Causa: el proceso de 5.1 conserva el PATH con el que arranco, asi que `Get-Command pwsh` no encuentra el pwsh recien instalado; la instalacion se informa como "no verificada" y no se relanza. Ademas no se revisa el codigo de salida de msiexec, y el relanzamiento con `Start-Process` abre otra ventana que se cierra al terminar, sin dejar ver el resumen.

Despues de instalar PowerShell 7, ubicar pwsh.exe aunque el PATH del proceso este desactualizado y relanzar el script en la misma consola, devolviendo su codigo de salida.
