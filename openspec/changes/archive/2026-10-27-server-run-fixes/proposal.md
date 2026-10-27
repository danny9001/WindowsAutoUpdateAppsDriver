# Correcciones tras la ejecucion en servidor

Ejecucion con -Verbose en LPZVMAD01 (Windows Server 2022, VMware), 2026-10-27:

- Windows Update mostro y conto tres veces la misma actualizacion (KB2267602, estado ADI): PSWindowsUpdate devuelve el mismo update en cada etapa (aceptar, descargar, instalar). El resumen dijo "Windows Update (3)" por una sola actualizacion.
- El fallo de Npcap se resumio como "codigo 0 o instalacion no confirmada", aunque RZGet habia informado la causa ("Installation failed: Npcap error: WARNING: Product not detected after installation").
- En modo detallado, las lineas [diag] quedaban pegadas a "[1/2] Npcap ...", porque esa linea se escribe sin salto para anadir el resultado.
- La linea de proxy salia vacia cuando no hay proxy.

Npcap en si no se corrige en el script: la edicion gratuita no admite instalacion silenciosa (solo Npcap OEM), y debe excluirse en el JSON del equipo con RuckZuck.SkipShortNames.
