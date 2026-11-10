# Instalación

Comienza aquí en un equipo que nunca haya utilizado este repositorio.

El Dockerfile, el Makefile, las topologías de Chutney, el paquete Python `torlab`, las pruebas offline y los scripts especializados están en `labs/es/`.

## Requisitos

| Herramienta | Para qué se necesita | Cómo comprobarla |
|---|---|---|
| **Docker** | Construir la imagen y ejecutar la red Tor privada | `docker run --rm hello-world` |
| **Python 3.11 o posterior** | Cliente educativo `torlab` | `python3 --version` |
| **`cryptography`** | X25519, Ed25519 y AES | `python3 -c "import cryptography; print(cryptography.__version__)"` |
| **`pytest`** | Ejecutar la suite local; la cifra de 53 corresponde solo a la referencia original | `python3 -m pytest --version` |
| **Rust (`cargo`)** | **Solo** para el laboratorio 20, que compila Arti | `cargo --version` |

Desde la raíz del repositorio, instala las dependencias Python del proyecto en un entorno virtual mediante:

```bash
python3 -m pip install -r requirements.txt
```

No necesitas instalar `stem` en el equipo anfitrión: los tres laboratorios que lo utilizan (11, 16 y 18) se ejecutan dentro del contenedor, que ya lo incluye.

Espacio en disco: aproximadamente **3 GB** para la imagen Docker, las fuentes de tor y el estado de la red. El laboratorio 20 requiere alrededor de **2 GB** adicionales para compilar Arti.

Sistema operativo: el laboratorio original se desarrolló y probó en Linux. En macOS, Docker funciona dentro de una máquina virtual; `--network host` se comporta de otra manera, por lo que la red necesita adaptaciones y los laboratorios de captura que utilizan `lo` (10 y 12) no funcionan sin cambios.

## Paso 1: construir la imagen

Comando previsto desde la raíz del repositorio:

```bash
make -C labs/es/laboratorio image
```

La imagen se basará en el laboratorio de referencia: compilará tor 0.4.9.13 desde las fuentes e incluirá Chutney, obfs4proxy, snowflake-client, `tshark` y `curl`. La primera construcción puede durar varios minutos; en el equipo de las pruebas originales tardó alrededor de trece minutos sin caché y descargó varios cientos de megabytes.

¿Por qué compilar tor en vez de instalar el paquete de la distribución?

- Su versión queda **fijada** en el Dockerfile (`ARG TOR_VERSION`), lo que permite reproducir resultados a lo largo del tiempo.
- Se necesita `--enable-gpl` para incluir el módulo de prueba de trabajo de servicios onion (laboratorio 9, capítulo 15). Comprueba la compilación y no supongas que todos los paquetes la incluyen.
- Tener las fuentes disponibles forma parte del propósito del libro: cuando una especificación no responde a una pregunta, se puede consultar el código en `src/core/or/`.

Comprobación prevista, una vez construida la imagen:

```bash
docker run --rm torbook-es-lab:latest tor --version
```

La etiqueta `torbook-lab:latest` pertenece a la referencia original. El Makefile español utiliza **`torbook-es-lab:latest`** para evitar sobrescribir imágenes de otras ediciones.

## Paso 2: iniciar la red

Comando previsto:

```bash
make -C labs/es/laboratorio start
```

La topología contiene diez nodos y se crea con Chutney. Las autoridades votan cada veinte segundos, por lo que el primer consenso aparece rápidamente. En la red de referencia, el arranque tardó unos dos minutos y medio.

```bash
make -C labs/es/laboratorio verify
```

Resultado de referencia: `successes:4 failures:0`. Chutney transmite datos de prueba y verifica su entrega de extremo a extremo. **No es una prueba realizada todavía sobre la edición española**.

Si aparece algún problema, consulta [Resolución de problemas](Resolucion-de-problemas.md).

## Paso 3: verificar los laboratorios

La suite offline española está incorporada. Para ejecutarla desde la raíz del repositorio, sin confundirla con la ejecución de todos los experimentos:

```bash
PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test
```

El número histórico de **53 pruebas** procede de la edición de referencia. El total real y los resultados de la suite española deben establecerse ejecutándola; eso tampoco valida por sí solo los experimentos de red ni las cifras históricas.

Los scripts especializados y sus pruebas offline están en `labs/es/laboratorio/`. Una entrada agrupada es `make -C labs/es test` desde la raíz del repositorio. Véase [Verificación automática](Verificacion-automatica.md).

## Paso 4 (opcional): construir el libro

El proyecto original dispone de una orden:

```bash
make book-pdf
```

Esta orden construye el **original italiano**, no la edición española. El `Makefile` de `source/es/` define `check`, `pdf` y `epub`. Desde la raíz y con las herramientas LaTeX instaladas, se pueden invocar `make -C source/es check`, `make -C source/es pdf` y `make -C source/es epub`.

## Detener y limpiar la red

Comandos previstos:

```bash
make -C labs/es/laboratorio stop      # detener nodos y conservar las claves y datos
make -C labs/es/laboratorio clean     # detener la red y eliminar labs/es/laboratorio/net/
```

El directorio generado `labs/es/laboratorio/net/` contendrá claves privadas de nodos de prueba. No deberá incorporarse al control de versiones ni publicarse. Aunque pertenezcan a una red de juguete, conviene tratarlas con el cuidado que exigirían unas claves reales.
