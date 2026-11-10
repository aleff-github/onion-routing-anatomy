# Entorno de laboratorio — Español

Este árbol contiene el entorno didáctico en español de *Anatomía de Tor*. Las fuentes, los ejemplos y la documentación están separados por idioma. **Separar directorios no significa aislar contenedores ni redes**: la ejecución de Chutney utiliza `--network host`, con puertos del anfitrión que pueden coincidir con los de otras ediciones. No inicies simultáneamente redes de laboratorio que compartan estos recursos.

## Contenido

Están incluidos el Dockerfile, los Makefile, las topologías privadas Chutney `book` y `book-bridge`, los módulos y pruebas Python de `torlab`, los scripts especializados de los laboratorios 10–11, 13–14 y 16–18 y el generador de configuración de Arti del laboratorio 20. Los demás laboratorios disponen de materiales didácticos en `codigo/` y `wiki/` según su alcance.

- `laboratorio/`: Dockerfile, redes privadas Chutney, scripts especializados y pruebas offline.
- `codigo/`: cliente educativo `torlab`, pruebas unitarias y recursos reproducibles.
- `wiki/`: documentación traducida de los laboratorios.
- `datos/`: datos de referencia y descargas históricas opcionales. `make data` consulta CollecTor por HTTPS solo cuando se solicita; la comprobación de cabecera **no verifica las firmas del consenso**.

## Comandos desde la raíz del repositorio

Se requiere un checkout completo, con Python, pytest y las dependencias indicadas para cada herramienta. La construcción de Docker puede necesitar acceso a Internet para obtener Tor, Chutney y paquetes.

```bash
make -C labs/es test       # torlab y ocho suites especializadas offline
make -C labs/es data       # descarga opcional de datos históricos públicos
make -C labs/es image      # construye la imagen Docker privada
make -C labs/es start      # arranca la topología book en el anfitrión
make -C labs/es verify     # pytest + verificación de la red Chutney activa
make -C labs/es status
make -C labs/es stop
```

`test` no ejecuta todos los experimentos del libro. `verify` vuelve a ejecutar esos tests y comprueba la red activa con Chutney; **un resultado correcto tampoco certifica los veinte laboratorios**. Para distinguir las pruebas de los experimentos y consultar resultados esperados, véase [la wiki de verificación](wiki/Verificacion-automatica.md).

## Topologías y precauciones

La red `book` tiene diez nodos e incluye un servicio onion. La topología `book-bridge` utiliza doce nodos para el puente obfs4 y **no** incluye el servicio onion ordinario. Para seleccionar la alternativa, primero detén la red anterior y revisa el estado generado:

```bash
make -C labs/es/laboratorio stop
# Inspecciona y conserva los datos o las claves que debas mantener.
make -C labs/es/laboratorio clean
make -C labs/es/laboratorio start NETWORK=book-bridge
make -C labs/es/laboratorio verify
```

**Atención: `clean` es destructivo.** Detiene el entorno y elimina `labs/es/laboratorio/net/`, incluidas claves privadas, identidades de nodos y estado generado. No lo utilices sin revisar y preservar previamente lo necesario. `stop` no elimina por sí mismo estos datos.

La imagen `torbook-es-lab:latest` y el contenedor `torbook-es-network` tienen nombres exclusivos de esta edición, pero los puertos se comparten con el anfitrión. Utiliza un equipo de pruebas controlado. No publiques `laboratorio/net/` ni claves generadas; ejecuta experimentos activos únicamente en la red privada de laboratorio, nunca contra repetidores Tor públicos o servicios de terceros.

