# Diseno

- Windows Update: deduplicar el resultado de Get-WindowsUpdate por KB y titulo antes de mostrarlo y contarlo (funcion Get-UniqueWindowsUpdates, probable sin PSWindowsUpdate).
- RuckZuck: cuando la instalacion no se confirma, el resumen incluye la ultima linea de error de RZGet (`ERR`, `FTL` o `Installation failed`) si existe, ademas del log.
- Modo detallado: las lineas de progreso que hoy usan -NoNewline (RuckZuck, WinGet, Intel) terminan la linea cuando el modo detallado esta activo, para que las lineas [diag] no se mezclen; sin modo detallado la salida no cambia.
- Proxy: mostrar "sin proxy" cuando GetProxy no devuelve direccion o devuelve la misma URL.

Validar con pruebas: duplicados de Windows Update, mensaje de fallo de RuckZuck con la causa, y todas las pruebas existentes.
