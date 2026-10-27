# Diseno

`.gitattributes` con `*.ps1 -text` (tambien .psm1 y .psd1): git no convierte saltos de linea en esos archivos, sin importar core.autocrlf. `eol=crlf` no alcanza, porque el repositorio seguiria guardando LF y la descarga raw de GitHub entregaria LF.

Conversion de todos los .ps1 versionados (script, pruebas y archivados) a CRLF a nivel de bytes: cada 0x0A sin 0x0D previo pasa a 0x0D 0x0A. Asi se conservan el BOM y cualquier codificacion compatible con ASCII; se verifica antes que ninguno sea UTF-16. Despues, `git add --renormalize`.

Validacion: todas las pruebas y la sintaxis en Windows PowerShell 5.1; tras subir, el SHA-256 de la copia local, del blob del commit y de la descarga raw de GitHub deben coincidir.

Resumen de RuckZuck: quitar el punto final de la causa antes de agregar "; log".
