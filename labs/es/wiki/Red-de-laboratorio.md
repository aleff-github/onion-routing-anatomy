# La red de laboratorio

Una red Tor completa —con autoridades de directorio, repetidores y un servicio onion— que utiliza servicios locales en `127.0.0.1` dentro de Docker. **Atención:** el Makefile emplea `--network host`, por lo que el contenedor **comparte la red del anfitrión** y no proporciona por sí solo aislamiento de red. Casi todos los laboratorios del libro utilizan esta topología privada. El capítulo 19 ofrece la explicación completa.

## ¿Por qué ejecutar una red propia?

No debes experimentar en la red Tor pública. Los paquetes enviados allí atraviesan repetidores administrados por voluntarios junto a tráfico de personas que dependen de Tor para su seguridad. Una acción inocua en una red privada puede convertirse en un ataque contra otras personas en la red pública.

En una red propia es posible realizar pruebas que serían inapropiadas fuera de ella: alterar deliberadamente un MAC para inspeccionar la respuesta de un repetidor, superar el límite de `RELAY_EARLY`, activar defensas contra DoS, descifrar tu propia sesión TLS y examinar sus celdas una a una.

## Topología

Diez nodos, todos en `127.0.0.1`:

| Nodo | Función | ORPort | ControlPort | Otros |
|---|---|---:|---:|---|
| `000a`, `001a`, `002a` | Autoridad de directorio y repetidor | 5100–5102 | 8000–8002 | DirPort 7100–7102 |
| `003r`, `004r`, `005r` | Repetidor intermedio | 5103–5105 | 8003–8005 | |
| `006e`, `007e` | Salida | 5106, 5107 | 8006, 8007 | Salidas hacia `127.0.0.0/8` |
| `008c` | Cliente | — | 8008 | SocksPort 9008 |
| `009h` | Servicio onion v3 | — | 8009 | Puerto virtual 5858 → `127.0.0.1:4747` |

**Regla de puertos:** el nodo *n* utiliza ORPort `5100+n`, ControlPort `8000+n` y, si es cliente, SocksPort `9000+n`. Así, el puerto `5103` siempre corresponde a `003r` y el `9008` al cliente.

Chutney asigna nombres como `test000a`, `test003r`, etc. El libro y la wiki utilizan a menudo las abreviaturas.

Al interpretar resultados, considera tres diferencias respecto a la red pública:

- Las autoridades votan **cada 20 segundos**, no una vez por hora; llega un consenso nuevo en menos de un minuto.
- Solo hay tres repetidores intermedios, por lo que las restricciones realistas de diversidad de rutas —repetidores distintos, redes /16 y familias diferentes— no se observan como en la red pública. El [laboratorio 7](Laboratorio-07-Rutas.md) las estudia con un consenso público histórico que **no se versiona en Git**; se obtiene por HTTPS mediante `make -C labs/es data`.
- Todos los nodos comparten una dirección IP, lo que vuelve ineficaces por diseño determinadas defensas.

La topología alternativa `book-bridge` **no es la red ordinaria más tres nodos**: su archivo Chutney define **12 nodos** (tres autoridades ordinarias, una autoridad de puentes, tres repetidores intermedios, dos salidas, un puente obfs4 y dos clientes, uno de ellos configurado para el puente). **No incluye el servicio onion `009h`**. Se utiliza para el [laboratorio 10](Laboratorio-10-Puente.md); vuelve a `book` antes de practicar con servicios onion.

## Comandos previstos

**Requisitos y precauciones:** ejecuta los comandos en un entorno Linux con Docker y GNU Make. La construcción de la imagen descarga Tor, Chutney y dependencias mediante Internet. La red privada utiliza **el espacio de red del anfitrión**, por lo que los servicios vinculados a loopback pueden alcanzar otros procesos del mismo equipo y los puertos coinciden con las demás ediciones. No inicies dos topologías lingüísticas simultáneamente. El control TCP `preflight` español ayuda a detectar puertos ocupados, pero **no es una garantía de aislamiento ni elimina las posibles carreras de puertos**.

Desde la raíz del repositorio:

```bash
make -C labs/es/laboratorio image       # construir una imagen específica de la edición española
make -C labs/es/laboratorio start       # crear el contenedor y los nodos; esperar al arranque
make -C labs/es/laboratorio verify      # comprobación de extremo a extremo con Chutney
make -C labs/es/laboratorio status      # mostrar el estado de los nodos
make -C labs/es/laboratorio shell       # abrir una consola en el contenedor
make -C labs/es/laboratorio stop        # detener los nodos; conservar el directorio net/
make -C labs/es/laboratorio clean       # eliminar también labs/es/laboratorio/net/

PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test
```

Los objetivos Make, las dos topologías y los scripts de prácticas están en el repositorio. Para la topología de puentes:

```bash
make -C labs/es/laboratorio clean
make -C labs/es/laboratorio start NETWORK=book-bridge
make -C labs/es/laboratorio verify
```

Al terminar, detén y limpia la red de puentes y vuelve a iniciar la topología ordinaria `book`. **Cuidado:** `clean` elimina **todo** `labs/es/laboratorio/net/`, incluidas las claves privadas, identidades onion y el estado generado. El objetivo `verify` no cambia automáticamente de topología: verifica la que esté activa y no sustituye las pruebas Python de los laboratorios.

**Importante para el aislamiento por idioma:** el Makefile original utiliza el nombre de contenedor `torbook-network`, la imagen `torbook-lab:latest` y puertos de anfitrión compartidos. La edición española emplea ahora `torbook-es-network` y `torbook-es-lab:latest`; el control `preflight` intenta detectar conflictos de puertos. No se deben iniciar dos topologías que compartan esos puertos al mismo tiempo.

## Ubicación de los archivos

```text
labs/es/laboratorio/net/nodes/             diez nodos (enlace a nodes.<marca temporal>)
labs/es/laboratorio/net/nodes/003r/
    torrc                 configuración generada por Chutney
    fingerprint           identidad RSA
    fingerprint-ed25519   identidad Ed25519 comprobada en los laboratorios
    notice.log            primer registro que consultar si algo falla
    pid
labs/es/laboratorio/net/nodes/008c/cached-microdescs.new    claves ntor de los repetidores
labs/es/laboratorio/net/nodes/009h/hidden_service/hostname  dirección .onion del servicio
```

`labs/es/laboratorio/net/` no debe estar bajo control de versiones. Contiene claves privadas, aunque sean de una red de pruebas. Se vuelve a crear cuando se limpia e inicia una red nueva; cada inicialización genera identidades nuevas. Por eso las huellas de la salida del lector no coincidirán con las impresas en el libro.

El módulo `torlab.laboratory` contiene funciones para leer estos archivos:

```python
from torlab.laboratory import relay
r = relay("003r")
print(r.port, r.id_ed.hex()[:16], r.ntor.hex()[:16])
```

## Normas de seguridad

Los scripts de laboratorio generan deliberadamente tráfico poco habitual: celdas malformadas, límites superados, sondeos repetidos y capturas de paquetes. Ejecútalos **únicamente en la red privada**. Ejecutarlos contra repetidores o servicios públicos perjudica a sus usuarios y puede ser ilegal. El capítulo 25 examina las cuestiones jurídicas pertinentes.

Los laboratorios 7, 15 y 19 estudian **documentos públicos históricos** de CollecTor, sin generar tráfico experimental hacia repetidores públicos ni usuarios de Tor. La primera descarga necesita **Internet por HTTPS**, aunque el procesamiento posterior de esos archivos sea local.
