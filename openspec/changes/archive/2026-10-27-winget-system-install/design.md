# Diseno

- `Test-IsSystemAccount`: `WindowsIdentity.GetCurrent().IsSystem`.
- `Install-WinGet`: como SYSTEM no se intenta `Add-AppxPackage` (dependencias ni bundle); se aprovisiona con `Add-AppxProvisionedPackage` (dependencias con -SkipLicense, bundle con -LicensePath). Fuera de SYSTEM, `Add-AppxPackage` del bundle deja de ser fatal: si falla se avisa y se aprovisiona igual. Como SYSTEM se omite el respaldo Microsoft.WinGet.Client.
- `Get-WinGetExecutable`: `Get-AppxPackage` dentro de try; si no da ruta, consulta con Windows PowerShell 5.1 (`-AllUsers`) y por ultimo busca `%ProgramFiles%\WindowsApps\Microsoft.DesktopAppInstaller_<version>_<arq>__8wekyb3d8bbwe\winget.exe` (la version mas alta).
- `Install-VCRedist`: 1638 es correcto ("ya instalado").
- `Update-WinGetApps`: si la instalacion falla, se agrega a Failures.
- `Ensure-PowerShell7`: el aviso de PS 5.1 se muestra una sola vez.

Pruebas: `tests/WinGetSystemInstall.Tests.ps1` con comandos simulados.
