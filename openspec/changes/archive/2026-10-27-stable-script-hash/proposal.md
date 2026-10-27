# Hash estable del script y puntuacion del resumen

El SHA-256 del modo detallado identifica la version del script en cada equipo, pero hoy depende de como se obtuvo la copia: el repositorio guarda los .ps1 con LF y git los convierte a CRLF segun la configuracion de cada equipo (copia local en LF: F3673E53...; checkout en Windows con CRLF: B5D61FF6...). La misma version da hashes distintos. Una conversion de saltos de linea tambien invalidaria una futura firma Authenticode.

Guardar los .ps1 con CRLF en el repositorio y sin conversion, para que clone, ZIP y descarga raw sean identicos byte a byte. De paso, quitar el punto final de la causa de RZGet en el resumen ("installation.; log").
