# Drivers del fabricante como alternativa a Windows Update

Hoy el paso 4 obtiene drivers solo de Windows Update (PSWindowsUpdate). Windows Update no siempre ofrece la ultima version del fabricante: en un HP ProBook 440 G10 (2026-10-27) HP Image Assistant recomendo Intel Dynamic Tuning 9.0.11911 (instalado 9.0.11701), y los drivers graficos y Wi-Fi de Intel (32.0.101.7092, 24.70) iban por delante de los de HP. Ademas, un dispositivo sin driver (codigo 28) queda sin solucion.

Agregar una fuente opcional de drivers del fabricante, usando solo herramientas oficiales que detectan que aplica al equipo y entregan paquetes firmados: HP Image Assistant, Dell Command Update y Lenovo (LSUClient o Thin Installer). Para equipos de otras marcas, buscar en el Microsoft Update Catalog solo los dispositivos sin driver. Usar pci.ids para nombrar en el resumen los dispositivos desconocidos. Windows Update sigue siendo la fuente predeterminada.
