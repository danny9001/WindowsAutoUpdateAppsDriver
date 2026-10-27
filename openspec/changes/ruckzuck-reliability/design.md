# Diseno

Ampliar JSON opcionalmente con RuckZuck.SkipShortNames, DelayDays, ScanTimeoutSeconds, InstallTimeoutSeconds y VersionCheckDays; valores predeterminados compatibles, con rangos validados. Mantener decisiones existentes de cada equipo. Consulta por ambito mediante proceso con salida y errores separados y archivos completos en Logs/RuckZuck; diferenciar error, timeout y lista vacia. Aplicar DelayDays solo a deteccion inicial y exclusiones por ShortName sin consultas extra por paquete.

Instalar por paquete con timeout, --retry y una verificacion posterior conjunta por ambito (sin delay para no interpretar paquetes pendientes como exitosos). Exit 0 no confirma instalacion: exigir mensaje de finalizacion y verificacion posterior; fallo/ambiguedad se registra como no confirmado. La reconsulta posterior se hara una sola vez por ambito para limitar llamadas. Al superar timeout se detiene solo el proceso RZGet iniciado; Windows Installer puede continuar y se advierte antes de seguir. RZGet cachea catalogo 30 min, pero cada invocacion hace escaneo/check updates; no afirmar que cada proceso descarga siempre el catalogo.

Comprobar release GitHub a intervalos, comparar digest oficial con archivo local, validar descarga antes de reemplazo y conservar version existente si falla; si digest no esta disponible no asumir integridad. DryRun no descarga ni actualiza RZGet.

Validar con ejecutable simulado y pruebas de configuracion y regresiones; sin instalar software. MemAI no disponible en esta sesion.
