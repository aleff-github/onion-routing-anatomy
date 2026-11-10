# Datos públicos históricos de investigación

Los laboratorios **7, 15 y 19** utilizan un consenso Tor archivado. El
consenso de prueba de Chutney incluido en la suite **no sustituye** al
documento público histórico necesario para reproducir las cifras del libro.

Desde la raíz del repositorio:

```bash
make -C labs/es data
```

El script descarga bajo demanda el archivo de Tor Project CollecTor de
septiembre de 2026 y extrae
`2026-09-23-15-00-00-consensus-microdesc` en
`labs/es/datos/collector/consensus-microdesc-2026-09-23-15`.
Solo se comprueba la **cabecera de formato**; ello no valida las firmas ni
reproduce automáticamente los cálculos. Para hacerlo se requieren los
certificados de autoridades correspondientes y la ejecución de las pruebas.

La descarga utiliza HTTPS normal, sin experimentos contra repetidores
públicos de Tor. Los datos descargados quedan excluidos de Git.

