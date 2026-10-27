# Reemplazo conjunto de RZGet.exe y RZGet.exe.config

Cerrar el riesgo identificado en sync-rzget-config: los reemplazos sucesivos no son atomicos y una falla del segundo puede dejar el ejecutable y la configuracion de releases distintas. Reemplazar ambos archivos como un par: si uno falla, restaurar los dos archivos anteriores. Recuperar tambien el par si una ejecucion se interrumpio a mitad del reemplazo y limpiar temporales huerfanos.
