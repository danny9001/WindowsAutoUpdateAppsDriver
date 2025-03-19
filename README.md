
# EN VERSION
# WindowsAutoUpdateAppsDriver
The script automatically updates applications and drivers on Windows. It detects if the system is a server and skips updates for Windows Store and Winget in that case. It logs the execution in a log file. It updates Windows Store apps, Chocolatey packages, Winget packages, RuckZuck packages, and drivers from Windows Update.

# Automatic Update Scripts Manual

## Introduction

This manual describes how to use the UpdateAppsDrivers3.ps1 script and the script to create a scheduled task that runs UpdateAppsDrivers3.ps1 every day.

## Requirements

- PowerShell
- Internet connection

## Script `UpdateAppsDrivers3.ps1`

### Description

The UpdateAppsDrivers3.ps1 script automatically updates applications and drivers on a Windows system. It detects if the system is a server and skips updates for Windows Store and Winget if so.

### Credits

- **Author:** Daniel Landivar
- **License:** CC BY-NC (Attribution-NonCommercial)
- **Editor:** Microsoft Copilot

### Functions

- **Update-WindowsStoreApps:** Updates Windows Store apps.
- **Update-WingetApps:** Updates Winget packages.
- **Update-RuckZuckApps:** Updates RuckZuck packages.
- **Update-Drivers:** Updates drivers from Windows Update.

### Usage

1. Download the Update `UpdateAppsDrivers3.ps1` script.
2. Run the script in PowerShell.

```powershell
.\UpdateAppsDrivers3.ps1
```

## Script to Create Scheduled Task

### Description

This script creates a scheduled task that runs UpdateAppsDrivers3.ps1 every day at the user-specified time. It also creates a folder at the user-specified location and copies the UpdateAppsDrivers3.ps1 script to that folder.

### Credits

- **Author:** Daniel Landivar
- **License:** CC BY-NC (Attribution-NonCommercial)
- **Editor:** Microsoft Copilot

### Usage

1. Download the script to create the scheduled task.
2. Run the script in PowerShell..

```powershell
.\CreateTask.ps1
.\UpdateAppsDrivers3.ps1
```

3. Follow the instructions to enter the task execution time and the location of the folder where the script will be copied.

### Example

```powershell
Enter the task execution hour (24-hour format, e.g., 03 for 3 AM, 14 for 2 PM): 03
Enter the task execution minutes (e.g., 30 for 2:30 PM): 30
Enter the location and name of the folder where the script will be copied (e.g., C:\ScriptAutoUpdate)
```

## Notas

- Ensure you have administrator permissions to run the scripts and create scheduled tasks.
- The specified folder must have enough space to store the script.

## Contacto

For any inquiries or modifications, you can contact the author:

- **Author:** Daniel Landivar
- **License:** CC BY-NC (Attribution-NonCommercial)
- **Editor:** Microsoft Copilot

# ES VERSION
# WindowsAutoUpdateAppsDriver
El script actualiza automáticamente aplicaciones y controladores en Windows. Detecta si es un servidor y omite actualizaciones de la Tienda Windows y Winget en ese caso. Registra la ejecución en un archivo de log. Actualiza aplicaciones de la Tienda Windows, paquetes de Chocolatey, Winget y RuckZuck, y controladores desde Windows Update.

# Manual de Uso de Scripts de Actualización Automática

## Introducción

Este manual describe cómo utilizar los scripts `UpdateAppsDrivers3.ps1` y el script para crear una tarea programada que ejecute `UpdateAppsDrivers3.ps1` todos los días.

## Requisitos

- PowerShell
- Conexión a Internet

## Script `UpdateAppsDrivers3.ps1`

### Descripción

El script `UpdateAppsDrivers3.ps1` actualiza automáticamente las aplicaciones y controladores en un sistema Windows. Detecta si el sistema es un servidor y omite las actualizaciones de la Tienda Windows y Winget si es así.

### Créditos

- **Autor:** Daniel Landivar
- **Licencia:** CC BY-NC (Reconocimiento-NoComercial)
- **Editor:** Microsoft Copilot

### Funciones

- **Update-WindowsStoreApps:** Actualiza las aplicaciones de la Tienda Windows.
- **Update-ChocolateyApps:** Actualiza los paquetes de Chocolatey.
- **Update-WingetApps:** Actualiza los paquetes de Winget.
- **Update-RuckZuckApps:** Actualiza los paquetes de RuckZuck.
- **Update-Drivers:** Actualiza los controladores desde Windows Update.

### Uso

1. Descargue el script `UpdateAppsDrivers3.ps1`.
2. Ejecute el script en PowerShell.

```powershell
.\UpdateAppsDrivers3.ps1
```

## Script para Crear Tarea Programada

### Descripción

Este script crea una tarea programada que ejecuta `UpdateAppsDrivers3.ps1` todos los días a la hora especificada por el usuario. También crea una carpeta en la ubicación especificada por el usuario y copia el script `UpdateAppsDrivers3.ps1` a esa carpeta.

### Créditos

- **Autor:** Daniel Landivar
- **Licencia:** CC BY-NC (Reconocimiento-NoComercial)
- **Editor:** Microsoft Copilot

### Uso

1. Descargue el script para crear la tarea programada.
2. Ejecute el script en PowerShell.

```powershell
.\CreateTask.ps1
.\UpdateAppsDrivers3.ps1
```

3. Siga las instrucciones para ingresar la hora de ejecución de la tarea y la ubicación de la carpeta donde se copiará el script.

### Ejemplo

```powershell
Ingrese la hora de ejecución de la tarea (formato 24 horas, ej. 03 para las 3 AM, 14 para las 2 PM): 03
Ingrese los minutos de ejecución de la tarea (ej. 30 para las 2:30 PM): 30
Ingrese la ubicación y nombre de la carpeta donde se copiará el script (ej. C:\ScriptAutoUpdate)
```

## Notas

- Asegúrese de tener permisos de administrador para ejecutar los scripts y crear tareas programadas.
- La carpeta especificada debe tener suficiente espacio para almacenar el script.

## Contacto

Para cualquier consulta o modificación, puede contactar al autor:

- **Autor:** Daniel Landivar
- **Contacto:** danny9001@gmail.com
- **Licencia:** CC BY-NC (Reconocimiento-NoComercial)
- **Editor:** Microsoft Copilot
