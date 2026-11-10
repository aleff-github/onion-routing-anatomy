# Laboratorio 12 — Celdas dentro de TLS

| | |
|---|---|
| **Capítulo** | 20 — Observar el tráfico: Wireshark y registros |
| **¿Requiere la red?** | Sí |
| **Requisitos previos** | Laboratorios 1–4 |
| **Duración** | De una a dos horas |
| **Módulo** | `labs/es/codigo/torlab/traffic.py` |

## Qué demuestra

Este laboratorio permite mirar dentro de una conexión Tor **porque conocemos las claves de nuestra propia sesión TLS**. Capturamos tráfico propio con `tcpdump`, exportamos las claves de nuestra conexión mediante `SSLKEYLOGFILE` y dejamos que `tshark` descifre la captura. Así pueden reconstruirse las celdas Tor una por una y en el orden del intercambio.

La diferencia es esencial: desciframos **nuestro propio tráfico**, utilizando claves exportadas voluntariamente por nuestro programa. No interceptamos ni atacamos conexiones de otras personas.

## Preparación

Ejecutar desde la raíz del repositorio y solo contra la red privada. Construir la imagen antes del primer arranque; las redes de distintos idiomas comparten puertos del anfitrión y no deben ejecutarse a la vez.

```bash
# Solo la primera vez: make -C labs/es/laboratorio image
make -C labs/es/laboratorio start
export PYTHONPATH=labs/es/codigo
```

**Seguridad y estado:** el ejemplo sustituye `labs/es/laboratorio/net/capture.pcap` y `keys.log` de ejecuciones anteriores. Guardarlos aparte si fuera necesario. **No publicar ni compartir el registro de claves TLS**, que permite descifrar la sesión registrada. El contenedor monta el árbol de laboratorio en `/lab`.

El módulo `traffic.py` incluye una prueba offline con una captura de referencia. El contenedor figura en la infraestructura de `labs/es/laboratorio/`.

## Ejecutar el experimento

El procedimiento de referencia, adaptado a las rutas previstas en español, consta de tres fases: capturar el tráfico hacia `004r`, generar un canal exportando sus secretos TLS y reconstruir las celdas de un flujo descifrado.

```bash
python3 - <<'PY'
import os, subprocess, time
from torlab.cells import CellCommand as C
from torlab.circuit import build
from torlab.laboratory import relay, NODES
from torlab.traffic import cells_from_follow as parse

network = "torbook-es-network"
keys = NODES.parent / "keys.log"
capture = NODES.parent / "capture.pcap"
# Archivos de experimentación: se reemplazan los resultados anteriores.
keys.unlink(missing_ok=True)
capture.unlink(missing_ok=True)

# 1. capturar únicamente el tráfico del puerto local 5104
subprocess.run(["docker", "exec", "-u", "0", "-d", network, "sh", "-c",
                "timeout 12 tcpdump -i lo -w /lab/net/capture.pcap 'tcp port 5104'"],
               check=True)
time.sleep(2)

# 2. abrir un canal privado y exportar sus claves TLS
previous = os.environ.get("SSLKEYLOGFILE")
os.environ["SSLKEYLOGFILE"] = str(keys)
try:
    circuit = build([relay("004r")], cc=False)
    circuit.channel.sock.close()
finally:
    if previous is None:
        os.environ.pop("SSLKEYLOGFILE", None)
    else:
        os.environ["SSLKEYLOGFILE"] = previous
# Esperar a que termine la captura antes de abrirla con tshark.
time.sleep(12)
if not keys.exists() or not keys.stat().st_size:
    raise RuntimeError("No se han exportado secretos de la sesión TLS")
keys.chmod(0o600)
print("Líneas del registro de claves TLS:", len(keys.read_text().splitlines()))

# 3. identificar flujos TCP TLS y reconstruir las celdas
opts = ["-r", "/lab/net/capture.pcap", "-d", "tcp.port==5104,tls",
        "-o", "tls.keylog_file:/lab/net/keys.log"]
scan = subprocess.run(["docker", "exec", network, "tshark", *opts,
                       "-Y", "tls && tcp.port==5104", "-T", "fields", "-e", "tcp.stream"],
                      check=True, capture_output=True, text=True)
stream_ids = sorted({int(v) for v in scan.stdout.split() if v.isdigit()})
found = False
for stream_id in stream_ids:
    result = subprocess.run(["docker", "exec", network, "tshark", *opts,
                             "-q", "-z", f"follow,tls,raw,{stream_id}"],
                            check=True, capture_output=True, text=True)
    try:
        cells = parse(result.stdout)
        names = [(direction, C(cell.command).name)
                 for direction, cell, _ in cells]
    except (ValueError, IndexError):
        continue
    if len(names) >= 2 and [name for _, name in names[:2]] == ["VERSIONS", "VERSIONS"] \
            and "CREATED2" in [name for _, name in names]:
        print(f"Flujo {stream_id}:")
        for direction, cell, version in cells:
            print(f"  {direction} {C(cell.command).name} (cuerpo {len(cell.body)} byte)")
        found = True
        break
if not found:
    raise RuntimeError("Falta la secuencia VERSIONS / CREATED2; revisa la captura y las claves")
PY
```

**Correspondencia comprobada estáticamente:** `NODES` apunta a `labs/es/laboratorio/net/nodes`, por lo que `NODES.parent / "keys.log"` en el anfitrión se corresponde con `/lab/net/keys.log` dentro del contenedor. Esto procede del código de `torlab.laboratory` y del montaje `-v $(CURDIR):/lab` del Makefile.

## Resultado del entorno original

```text
TLS keys exported: 6 lines
flow 1:
   client VERSIONS (body 4 byte)
   relay VERSIONS (body 6 byte)
   relay CERTS (body 1446 byte)
   relay AUTH_CHALLENGE (body 36 byte)
   relay NETINFO (body 509 byte)
   client NETINFO (body 509 byte)
   client CREATE2 (body 509 byte)
   relay CREATED2 (body 509 byte)
```

Interpretación:

- Se trata del intercambio del [laboratorio 1](Laboratorio-01-Canal.md) visto desde una captura: las mismas celdas, en el mismo orden, reconstruidas a partir de bytes transportados dentro de TLS.
- No es posible prever el índice de flujo TLS. El nuevo ejemplo obtiene **todos los índices TCP** reconocidos como TLS en el puerto 5104 y busca una secuencia que empiece con dos `VERSIONS` e incluya `CREATED2`, sin limitarse a los ocho primeros índices; si no la encuentra, devuelve un error.
- `NETINFO`, `CREATE2` y `CREATED2` son celdas de **longitud fija** con un cuerpo rellenado hasta **509 bytes**. Con el protocolo de enlace v4/v5, cada celda fija completa mide **514 bytes** (4 de CircID, 1 de comando y 509 de cuerpo); `VERSIONS` y `CERTS` son de longitud variable. Sin las claves TLS no se pueden leer sus comandos cifrados.
- Las **seis líneas** son un resultado histórico, no un número garantizado: varían con la versión de TLS, la implementación y la sesión, y pueden incluir comentarios. En este proyecto las escribe el cliente Python mediante `ssl.SSLContext.keylog_filename`.

## ¿Qué puede verse sin las claves?

Esta es la pregunta central del capítulo 20. Un observador pasivo ve la dirección y el puerto del repetidor privado, una conexión TLS (TLS 1.3 en la captura histórica) y los tamaños y tiempos de los paquetes. El experimento no utiliza repetidores del consenso público de Tor. Sin las claves de sesión, no ve los comandos de celda, CircID ni cuántos circuitos lógicos comparten el canal.

Los tamaños y tiempos continúan siendo relevantes: son los datos empleados por los ataques de correlación de tráfico de extremo a extremo estudiados desde una perspectiva defensiva en el [laboratorio 16](Laboratorio-16-Correlacion.md).

## Prueba offline de una secuencia capturada

El vector `labs/es/codigo/torlab/test/data/follow-tls.txt` recoge los bloques hexadecimales de una captura descifrada del canal **propio** de la edición de referencia. Su contenido es evidencia técnica: se conserva sin cambios, y la prueba compara tanto la dirección del flujo como los nombres de comando `VERSIONS`, `CERTS`, `AUTH_CHALLENGE`, `NETINFO`, `CREATE2` y `CREATED2`.

```bash
PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test/test_traffic.py
```

 El resultado offline no certifica que `tcpdump`, `SSLKEYLOGFILE` y `tshark` funcionen todavía en la nueva red española.

En la API de `cells_from_follow`, los identificadores `client` y `relay` son valores de retorno conservados por compatibilidad; los textos explicativos de la guía y las salidas de `print` están en español.

## Verificación automática

La comprobación `lab12` del verificador **italiano** `scripts/verify_labs.py` busca dos `VERSIONS` iniciales y una `CREATED2`, pero la versión histórica solo explora los primeros ocho flujos e ignora algunos errores de procesos. El ejemplo actualizado de esta guía explora los flujos detectados y falla si no hay una secuencia completa. El test offline español `test_traffic.py` reconstruye la muestra guardada; **no demuestra** que una nueva captura o el descifrado dinámico funcionen,

## Problemas conocidos

| Síntoma | Causa |
|---|---|
| No aparece ninguna celda en ningún flujo TLS | Comprobar que Python exportó los secretos antes de abrir el socket, que TLS se decodifica en el puerto 5104 y que la captura contiene el intercambio completo. |
| `tshark` no puede abrir el pcap | Capturar paquetes dentro del contenedor necesita privilegios; el comando utiliza `docker exec -u 0`. |
| El pcap está vacío | `tcpdump` comenzó después del tráfico. Inicia primero la captura y espera un poco antes de conectarte. |
| Solo se descifra una parte del intercambio | La captura terminó mientras el canal todavía estaba activo; aumenta el tiempo permitido para capturar. |

