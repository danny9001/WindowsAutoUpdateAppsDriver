# WinGet como SYSTEM y resumen honesto

Ejecucion real del 2026-10-27 con -RunNow -UpdaterVerbose en 6 servidores. En lpzvmad01 y lpzvmad02 (Server 2022 sin WinGet) la instalacion fallo: como SYSTEM, `Add-AppxPackage` es rechazado (0x80073CF9, "the Local System account is not allowed") y ese error cortaba la instalacion antes de `Add-AppxProvisionedPackage` del bundle; el respaldo Microsoft.WinGet.Client tampoco funciona como SYSTEM ("Specified method is not supported"). Ademas:
- VC++ devolvio 1638 (ya hay una version igual o mas nueva) y se informo como fallo.
- El resumen dijo "sin incidencias" aunque WinGet no se pudo instalar.
- En pwsh 7 de Server 2022, `Get-AppxPackage` falla al importar el modulo, asi que `Get-WinGetExecutable` no encuentra un WinGet aprovisionado.
- El aviso "Detectado Windows PowerShell" salia dos veces al instalar PS7.

En lpvmhv01 y lpzvmpr02 WinGet ya funciona como SYSTEM desde `C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*\winget.exe`.
