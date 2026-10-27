# Diseno

## Fuentes evaluadas

| Fuente | Que entrega | Decision |
|---|---|---|
| pci.ids (github.com/pciutils/pciids, GPL-2+/BSD-3) | Nombres de fabricante y dispositivo por ID PCI; sin drivers | Solo identificacion en el reporte |
| devicehunt.com, pcilookup.com | Busqueda web de IDs PCI/USB; sin drivers, API ni terminos de uso | No se usan; pci.ids cubre lo mismo con licencia clara |
| HP Image Assistant (WinGet HP.ImageAssistant) y HP CMSL | Analisis del equipo e instalacion silenciosa de SoftPaqs firmados, incluido BIOS/firmware | Fuente del fabricante del equipo (HP) |
| Dell Command Update (WinGet Dell.CommandUpdate, dcu-cli) | Escaneo e instalacion silenciosa por tipo (driver, bios, firmware) | Fuente del fabricante del equipo (Dell) |
| Lenovo: LSUClient (MIT, PowerShell Gallery) o Thin Installer (WinGet) | Deteccion e instalacion silenciosa, incluido BIOS/firmware | Fuente del fabricante del equipo (Lenovo) |
| Catalogo de Intel DSA (https://dsadata.intel.com/data/en, zip publico) | 33 paquetes Intel (graficos, Wi-Fi, Bluetooth, LAN, NPU) con hardware IDs, version del driver, URL en downloadmirror.intel.com y hash SHA-1 | Fuente del fabricante de componentes (Intel) |
| NVIDIA (endpoint de busqueda no documentado usado por proyectos como ZenitH-AT/nvidia-update) | Ultimo driver por modelo de GPU; instalador con modo silencioso documentado | Opcional, fuera de la primera entrega |
| AMD Adrenalin, Realtek | Sin API ni modo silencioso documentado para el paquete de consumo | Quedan cubiertos por fabricante del equipo y Windows Update |
| Microsoft Update Catalog (modulo MSCatalog) | Drivers WHQL por hardware ID; sin API oficial | No se integra (decision del usuario) |
| Intel Driver & Support Assistant (aplicacion) | Sin linea de comandos para instalar | No se integra; se usa su catalogo |
| Snappy Driver Installer, DriverPack, station-drivers, DriversCloud | Paquetes reempaquetados por terceros, origen no verificable | Rechazadas |

Comparar versiones por cuenta propia solo es fiable si la fuente da la version del driver. El catalogo de Intel la da por componente (Components[].Version) y se compara con Win32_PnPSignedDriver. Los SoftPaq de HP dan la version del paquete (Bluetooth: SoftPaq 24.60.0.4 frente a driver 24.70.0.4), asi que para HP, Dell y Lenovo la deteccion se delega en su herramienta oficial.

Prueba en HP ProBook 440 G10 (2026-10-27): el catalogo de Intel detecto Wi-Fi AX211, Bluetooth y UHD Graphics, los tres ya en la ultima version (instalados antes con Intel DSA, por delante de HP: graficos HP 32.0.101.7088, Intel 32.0.101.7092). HP publica 25 SoftPaqs de drivers para la plataforma 8B78. Comparando versiones a mano parecia que el Intel Management Engine de HP (2613.9.28.0) era mas nuevo que el instalado (2603.9.4.0), pero el analisis real de HP Image Assistant no lo recomendo: solo Intel Dynamic Tuning (9.0.11701 -> 9.0.11911), sin BIOS ni firmware pendientes. Confirma que la deteccion debe quedar en la herramienta del fabricante.

## Decisiones del usuario

- Buscar en todas las fuentes: fabricante del equipo, fabricante de componentes (Intel) y Windows Update.
- Incluir BIOS y firmware del fabricante del equipo.
- Sin respaldo del Microsoft Update Catalog.

## Integracion

Nueva seccion `Drivers` en el JSON:

- `Sources`: lista ordenada; por defecto `["Oem","Intel","WindowsUpdate"]`. Quitar una entrada la desactiva.
- `IncludeFirmware`: `true` por defecto, segun la decision del usuario. Antes de instalar BIOS o firmware se suspende BitLocker por un reinicio (Suspend-BitLocker -RebootCount 1) solo si el volumen del sistema esta protegido; nunca se reinicia por cuenta propia, se respeta RebootPolicy y se marca reinicio pendiente.
- `InstallVendorTool`: `true`. Instala por WinGet la herramienta del fabricante si falta.
- `SkipIntelIds`: IDs del catalogo de Intel a omitir.

Orden: fabricante del equipo, despues Intel (solo si su version es mayor que la instalada, para no degradar lo que puso el fabricante) y al final Windows Update. Un fallo en una fuente se registra y no detiene las demas.

Fabricante del equipo (Win32_ComputerSystem):
- HP: `HPImageAssistant.exe /Operation:Analyze /Category:Drivers[,BIOS,Firmware] /Selection:All /Action:Install /Silent /Noninteractive /ReportFolder:<Logs> /SoftpaqDownloadFolder:<carpeta>`.
- Dell: `dcu-cli.exe /applyUpdates -updateType=driver[,bios,firmware] -reboot=disable -outputLog=<Logs>`.
- Lenovo: LSUClient `Get-LSUpdate | Where-Object Type ... | Install-LSUpdate`.
- Otras marcas: se informa que no hay herramienta y se sigue con Intel y Windows Update.

Intel: descargar el zip del catalogo, leer software-configurations.json, cruzar Components[].DetectionValues (tipo Default) con los hardware ID instalados y la version del sistema operativo (Files[].OperatingSystems). Para cada paquete mas nuevo: descargar de downloadmirror.intel.com, comprobar el SHA-1 del catalogo y exigir firma Authenticode valida de Intel (sin firma valida no se instala). Las entradas DetectionType Guid o Custom no se evaluan.

Windows Server (ProductType distinto de 1, incluye controladores de dominio): el paso se omite y los drivers quedan a cargo de Windows Update. HP Image Assistant, Dell Command | Update y LSUClient solo admiten equipos cliente, y el catalogo de Intel ofrece drivers de cliente. El fabricante "HPE" (ProLiant) no se trata como HP. Las herramientas de servidor (HPE Service Pack for ProLiant, Dell System Update, Lenovo XClarity) quedan fuera de este cambio. Las maquinas virtuales no tienen fabricante compatible ni hardware Intel en el catalogo, asi que no instalan nada.

DryRun solo analiza y lista en las tres fuentes. Los reportes y codigos de salida pasan al resumen y a Logs.

## Riesgos

- Intel marca casi todos sus paquetes con AllowSilentInstallation=false: DSA no los instala sin interaccion. Instalarlos en silencio depende de las opciones de cada instalador (graficos: --nouninstall en el catalogo; Wi-Fi y Bluetooth sin opciones publicadas). Requiere decision: instalar en silencio verificando cada instalador, o solo informar con enlace.
- El catalogo de Intel no esta documentado como API publica; si cambia el formato, el paso falla de forma controlada y no bloquea los demas.
- BIOS y firmware pueden dejar el equipo sin arrancar si se interrumpe la energia: se exige equipo conectado a corriente antes de instalarlos y se omiten con bateria.
- Un driver del fabricante del equipo puede ser mas antiguo que el instalado: las herramientas oficiales no degradan, e Intel solo instala versiones mayores.

## Validacion

Pruebas simuladas por fuente (comandos, codigos de salida, DryRun, firmware, cruce de hardware IDs y versiones, rechazo por hash o firma). Prueba real de solo analisis en el HP ProBook 440 G10. La instalacion real, sobre todo de BIOS, solo con confirmacion del usuario.
