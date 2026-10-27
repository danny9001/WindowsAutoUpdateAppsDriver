# Diseno

`Test-WinGetMsixPackage -Id`: `winget show --id <id> --exact`; es MSIX si alguna linea es "<campo>: msix" o "<campo>: appx" (la etiqueta "Installer Type" se traduce segun el idioma). Si winget show falla, no se considera MSIX y se intenta la actualizacion como antes.

En `Update-WinGetApps`, solo como SYSTEM (`Test-IsSystemAccount`), antes de cada `upgrade` se consulta el tipo; un MSIX se muestra OMITIDO y va a Skipped ("MSIX, requiere sesion de usuario"), sin contarlo como fallo. Fuera de SYSTEM no se consulta nada.

Comprobado con winget real: Microsoft.WindowsTerminal = msix; Microsoft.WindowsAppRuntime.1.5 = exe (se actualizo bien como SYSTEM en LPZVMGP00); Microsoft.VCRedist.2015+.x64 = burn.

Pruebas: WinGetContinuation (MSIX omitido como SYSTEM y el resto continua; sin consultas fuera de SYSTEM) y WinGetSystemInstall (deteccion msix/appx, etiqueta traducida, exe con URL .msix y error de winget show).
