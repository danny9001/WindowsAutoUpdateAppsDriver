# Omitir paquetes MSIX de WinGet como SYSTEM

Ejecucion real del 2026-10-27 en LPZVMNPS00: `winget upgrade --id Microsoft.WindowsTerminal` como SYSTEM fallo con "Installer failed with exit code: 0x80070002". Windows Terminal es MSIX y se registra por usuario; SYSTEM no puede actualizarlo y fallaria en cada ejecucion programada, ademas de sugerir una recuperacion `--interactive` sin sentido en una tarea. Decision del usuario: implementar la omision general en lugar de excluir el paquete en ese servidor.
