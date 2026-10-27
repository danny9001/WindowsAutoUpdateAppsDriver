# Continuar todos los paquetes WinGet

El filtro de IDs heredado de 7.1 excluye los paquetes Microsoft.VCRedist.2015+.x64/x86 porque contienen +. Corregir la extraccion y aislar errores por paquete para procesar todos los candidatos.

## Criterios
- Extraer los tres IDs del registro reportado, incluidos ambos VCRedist.
- Si OLE DB devuelve -1978335159 o lanza una excepcion, intentar ambos paquetes restantes.
- Usar la lista ya mostrada para evitar otra consulta con resultados distintos.
- Conservar el tratamiento existente de Edge y reinstalaciones.
