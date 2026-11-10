# Laboratorio 5 — Descargar un archivo: flujos, ventanas y SENDME

| | |
|---|---|
| **Capítulo** | 11 — Flujos y control de flujo |
| **¿Requiere la red?** | Sí, más un servidor web local |
| **Requisitos previos** | Laboratorios 1–4 |
| **Duración** | Unas tres horas de implementación; dos minutos para repetirlo |
| **Módulo previsto** | `labs/es/codigo/torlab/stream.py` |

## Qué demuestra

El cliente educativo puede descargar un megabyte completo atravesando tres repetidores y recibir el mismo resumen SHA-256 que el archivo original. En el segundo experimento hacemos algo que un cliente normal no debería: **dejar de enviar celdas `SENDME`**, contando cuántas celdas `DATA` envía la salida antes de detenerse. Esa cifra revela la ventana activa y hace visible la diferencia entre control de flujo histórico y control de congestión reciente.

## Preparación

Este experimento debe ejecutarse exclusivamente en la **red privada Tor/Chutney** de los laboratorios 1–4. Si está detenida, inicia antes el entorno `labs/es/laboratorio`. El cliente educativo no está previsto para la red pública de Tor. El servidor web debe ser alcanzable por el loopback de los repetidores del laboratorio.

Inicia un servidor web local en el puerto 8080 con un archivo de un megabyte:

```bash
mkdir -p /tmp/labweb && head -c 1048576 /dev/urandom > /tmp/labweb/grande.bin
sha256sum /tmp/labweb/grande.bin
cd /tmp/labweb && python3 -m http.server 8080 --bind 127.0.0.1 &
```

Después, desde la raíz del repositorio:

```bash
export PYTHONPATH=labs/es/codigo
```

> El puerto 8080 también se utiliza en la verificación completa de los laboratorios. Detén este servidor temporal antes de ejecutar las pruebas, o estas fallarán porque el puerto ya está ocupado.

## Ejecutar el experimento

```bash
python3 - <<'EOF'
import hashlib
import time
from pathlib import Path
from torlab.circuit import build
from torlab.laboratory import relay
from torlab.stream import Stream

circ = build([relay("003r"), relay("004r"), relay("006e")])
s = Stream(circ, 1)
t = time.time()
s.open("127.0.0.1", 8080)
s.send(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
r1 = s.receive_all()
print(f"flujo 1: {len(r1)} bytes en {time.time()-t:.2f} s, celdas DATA {s.reg.data_cells}, "
      f"SENDME del circuito {circ.sendme_sent}, otros {s.reg.others}")

s = Stream(circ, 2)  # segundo flujo, mismo circuito
t = time.time()
s.open("127.0.0.1", 8080)
s.send(b"GET /grande.bin HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
r2 = s.receive_all()
print(f"flujo 2: {len(r2)} bytes en {time.time()-t:.2f} s, celdas DATA {s.reg.data_cells}, "
      f"SENDME del circuito {circ.sendme_sent}, otros {s.reg.others}")

headers, sep, payload = r2.partition(b"\r\n\r\n")
if not sep or b" 200 " not in headers.split(b"\r\n", 1)[0]:
    raise RuntimeError("HTTP response is missing or is not 200 OK")
reference = Path("/tmp/labweb/grande.bin").read_bytes()
assert len(reference) == len(payload) == 1048576, "HTTP file length differs"
expected_sha = hashlib.sha256(reference).hexdigest()
received_sha = hashlib.sha256(payload).hexdigest()
assert received_sha == expected_sha, "download SHA-256 does not match local file"
print("SHA-256 recibido:", received_sha)
print("SHA-256 coincide con el archivo local")
EOF
```

## Resultado original de referencia

Los valores siguientes son ilustrativos y no se han obtenido al volver a ejecutar la red: el archivo usa datos aleatorios, las cabeceras HTTP y el listado de directorios varían, y el total de celdas depende del empaquetado. El script verifica realmente el HTTP 200, la longitud del archivo y el SHA-256 al ejecutarse.

```text
flujo 1: ... celdas DATA 1, ... SENDME del circuito 0, ...
flujo 2: ... celdas DATA 2120, ... SENDME del circuito 68, ...
SHA-256 recibido: <hash hexadecimal de 64 caracteres del archivo aleatorio>
SHA-256 coincide con el archivo local
```

Una apertura `BEGIN` correcta recibe `CONNECTED`. Para IPv4 puede contener ocho bytes (dirección y TTL), pero la especificación también admite un cuerpo vacío o un formato IPv6: `7f000001 00000708` es solo un ejemplo histórico, no un valor obligatorio. Los SENDME de circuito cuentan las celdas DATA **originadas por el salto final para los flujos de ese circuito**, no las que solamente atraviesan otros saltos. En el ejemplo 1 + 2120 celdas y un incremento de 31 producen floor(2121 / 31) = 68 SENDME, sin que esos valores sean constantes. Para 1048781 bytes HTTP se necesitan al menos ceil(1048781 / 498) = 2106 celdas; 2120 ilustra que algunas van parcialmente ocupadas.

## El error que hace útil el laboratorio

La primera versión colocó el contador `SENDME` de circuito dentro de **`Stream`**. El primer flujo, que apenas necesitaba unas celdas, funcionaba; el segundo, de un megabyte, terminaba con `DESTROY` enviado por la salida.

El motivo es que los `SENDME` de circuito cuentan las celdas `DATA` de **todos los flujos**. La salida había contado ya las del primer flujo y esperaba el siguiente `SENDME` antes de lo que calculaba el cliente. Este lo envió demasiado tarde, con un digest acumulativo distinto del esperado. La propuesta 289 exige cerrar el circuito en ese caso. Tras trasladar el contador a `Circuit`, el fallo desapareció.

Los `SENDME` de circuito están **autenticados**: incluyen el digest acumulativo asociado a la celda desencadenante. Quien no haya recibido y procesado realmente el tráfico no puede falsificarlos fácilmente para provocar una transmisión más rápida.

## Observar directamente las ventanas

```bash
python3 - <<'EOF'
from torlab.circuit import build
from torlab.laboratory import relay
from torlab.stream import Stream
for cc in (True, False):
    circ = build([relay("003r"), relay("004r"), relay("006e")], cc=cc)
    circ.count_received_data = lambda: None       # sin SENDME de circuito
    s = Stream(circ, 1)
    s.open("127.0.0.1", 8080)
    s.send(b"GET /grande.bin HTTP/1.0\r\n\r\n")
    circ.channel.sock.settimeout(6)
    try:
        s.receive_all()
    except TimeoutError:
        pass
    print(f"control de congestión={cc}: la salida se detiene tras {s.reg.data_cells} celdas DATA")
EOF
```

Estos valores corresponden a una configuración privada concreta: ventana inicial de congestión de 124 celdas (4 × `sendme_inc=31`) y antigua ventana de flujo de 500. Los parámetros de consenso y la versión de Tor pueden cambiar el resultado. **124 no son literalmente cuatro registros TLS**: son cuatro incrementos de 31 celdas DATA. **500** se obtiene al agotarse la ventana de flujo antes de la ventana de circuito de 1000. La salida deja de producir nuevas celdas DATA mientras espera confirmación, pero eso no garantiza que todos los datos pendientes estén en su búfer de aplicación.

```text
control de congestión=True: la salida se detiene tras 124 celdas DATA
control de congestión=False: la salida se detiene tras 500 celdas DATA
```

La clase didáctica `Stream` **no implementa SENDME a nivel de flujo**. Es adecuado cuando se negocia control de congestión (`cc=True`); con `cc=False` una transferencia grande se detendrá al agotar la ventana antigua de 500 celdas, incluso si los SENDME del circuito estuvieran activados. Se trata de una limitación intencionada para observar ese mecanismo, no de una implementación completa del régimen histórico.

## Verificación automática

El verificador italiano histórico `lab5` se encuentra en `scripts/verify_labs.py` y prueba el SHA-256 y los límites 124/500 bajo su configuración privada. La edición española ofrece módulos Python y un experimento manual Chutney, no un comando `lab5` autónomo y equivalente.

## Problemas conocidos

| Síntoma | Causa |
|---|---|
| `BEGIN rechazado: EXITPOLICY` | La salida rechaza el destino o el puerto; examina la política y los cambios del [laboratorio 14](Laboratorio-14-Politica-de-salida.md). |
| El circuito se destruye durante la descarga grande | El contador `SENDME` de circuito se guardó por flujo en vez de por circuito. |
| `BEGIN rechazado: CONNECTREFUSED` | La salida no puede conectar a 127.0.0.1:8080; comprueba la disponibilidad del servidor web. |

---

# Implementación detallada

La lógica principal ya está localizada en `labs/es/codigo/torlab/stream.py`, mientras que el control de `SENDME` de circuito reside en `circuit.py`. Es aquí donde el cliente educativo pasa de demostrar protocolos a transferir archivos reales.

## Abrir un flujo

```python
def begin_body(address: str, port: int, flag: int = 0) -> bytes:
    """ADDRPORT en minúsculas y terminado en NUL; omitir FLAGS si vale cero."""
    body = f"{address.lower()}:{port}".encode() + b"\x00"
    return body + (struct.pack(">I", flag) if flag else b"")

```

La función incluye tres detalles con niveles normativos distintos:

- **Minúsculas (SHOULD):** Tor recomienda `ADDRPORT` en minúsculas para reducir las huellas del cliente, pero el receptor **debe** aceptar también nombres con mayúsculas. No es un motivo obligatorio de rechazo.
- **Terminación NUL:** el campo es una cadena al estilo C y no una cadena con longitud antepuesta.
- **Omitir FLAGS si vale cero:** el campo opcional solo es necesario para comportamientos adicionales, como determinadas opciones de direcciones IPv6.

```python
def open(self, address: str, port: int) -> bytes:
    self.circ.send(RelayMessage(RelayCommand.BEGIN, self.id, begin_body(address, port)))
    _, msg = self._next()
    if msg.command == RelayCommand.END:
        raise CircuitError(f"BEGIN rechazado: {END_REASONS.get(msg.data[0], msg.data[0])}")
    if msg.command != RelayCommand.CONNECTED:
        raise CircuitError(f"respuesta inesperada a BEGIN: {msg.command}")
    return msg.data
```

Existe una diferencia intencionada entre este cliente didáctico y tor, importante para su identificación por huella. La especificación exige `EXTEND2` dentro de `RELAY_EARLY` y recomienda utilizar la reserva de celdas tempranas restante para aproximadamente los primeros ocho mensajes relay originados por el cliente que no estén destinados al primer salto. tor sigue esa recomendación: en `src/core/or/relay.c` utiliza `RELAY_EARLY` mientras `remaining_relay_early_cells > 0` en celdas donde `cpath_layer != origin_circ->cpath`. En consecuencia, suele enviar el primer `BEGIN` con `RELAY_EARLY`, mientras el cliente educativo usa `RELAY` ordinaria salvo para `EXTEND2`.

La consecuencia es real: un guardia que cuente celdas tempranas puede distinguir a este cliente simplificado de tor. Se mantiene ese comportamiento didáctico para introducir un concepto en cada laboratorio, pero la figura del intercambio completo del libro muestra el comportamiento de producción.

La salida responde con `CONNECTED`, que transporta dirección resuelta y TTL, o con `END` y un código de motivo. Los motivos son útiles: `EXITPOLICY` significa que la salida rechaza ese destino y otra podría funcionar; `CONNECTREFUSED` indica que la salida alcanzó el destino pero el extremo remoto rechazó la conexión. Véase el [laboratorio 14](Laboratorio-14-Politica-de-salida.md).

El protocolo también permite enviar datos de aplicación antes de recibir `CONNECTED`, ahorrando una ida y vuelta del circuito. Este cliente espera deliberadamente a `CONNECTED` para facilitar la comprensión.

## Control de flujo y el error fundamental

```python
def count_received_data(self) -> None:
    """Llamar por cada celda DATA recibida del último salto: enviar un SENDME
    autenticado (versión 1) cada `sendme_inc` celdas."""
    est = dict(self.exit_extensions)
    sendme_inc = est[2][0] if 2 in est else 100
    self.data_to_ack += 1
    if self.data_to_ack == sendme_inc:
        self.data_to_ack = 0
        # Digest acumulativo tras la celda reconocida que provoca SENDME:
        # sendme_digest en src/core/crypto/relay_crypto_tor1.c.
        digest = self.crypto.hops[-1].backward.digest.digest()
        body = struct.pack(">BH", 1, 20) + digest
        self.send(RelayMessage(RelayCommand.SENDME, 0, body))
        self.sendme_sent += 1
```

**Este método pertenece a `Circuit`, no a `Stream`.** En la primera implementación, cada flujo llevaba un contador propio y calculaba el momento equivocado para enviar el digest tras haber recibido otras celdas en el circuito.

También importan los demás elementos:

- **`sendme_inc`** procede de la extensión 2 negociada con la salida ([laboratorio 3](Laboratorio-03-Handshake.md)). Vale 31 con control de congestión y 100 con control de flujo histórico en este entorno. Es un parámetro negociado, no una constante inmutable del cliente.
- **El digest** es el resumen acumulativo en dirección de vuelta del último salto, *después* de procesar la celda `DATA` que desencadenó el mensaje. Es estado interno del circuito conocido por quien recibió el tráfico.
- **Versión 1 y longitud 20** codifican el `SENDME` de circuito autenticado mediante SHA-1. La versión 0 carecía del digest y permitía acuses de recibo falsificados; la propuesta 289 introdujo la autenticación.
- **StreamID cero** designa un mensaje de control del circuito. Los flujos tienen ventanas y acuses de recibo propios.

> Un `SENDME` autenticado no es una firma digital. Se parece más a una **prueba de recepción**: conocer el digest acumulativo requerido demuestra que el receptor procesó las celdas correspondientes.

## Bucle de recepción

```python
def receive_all(self) -> bytes:
    """Lee DATA hasta END y envía los SENDME de circuito necesarios."""
    parts = []
    while not self.closed:
        _, msg = self._next()
        if msg.command == RelayCommand.DATA:
            parts.append(msg.data)
            self.reg.received_data += len(msg.data)
            self.reg.data_cells += 1
            self.circ.count_received_data()
        elif msg.command == RelayCommand.END:
            self.closed = True
            self.reg.others.append(f"END {END_REASONS.get(msg.data[0] if msg.data else 1)}")
        else:
            self.reg.others.append(RelayCommand(msg.command).name)
    return b"".join(parts)
```

Contar y reconocer datos ocurre **dentro** del bucle de recepción. Si el cliente deja de leer, también deja de reconocer las celdas y el remitente acaba alcanzando su límite de ventana. Así, el control de flujo se deriva naturalmente de la lectura.

`self.reg` acumula estadísticas —bytes, celdas `DATA` y otros mensajes—, útiles para explicar por qué una transferencia real suele necesitar más celdas que el mínimo `ceil(bytes / 498)`: las salidas envían datos conforme llegan, sin esperar a llenar cada celda.

## Medir una ventana

```python
circ = build(path, cc=cc)
circ.count_received_data = lambda: None      # no enviar mensajes SENDME
```

Reemplazar temporalmente el método por una función vacía es una técnica **solo de laboratorio**. Permite contestar directamente una pregunta que de otro modo quedaría abstracta: **¿cuántas celdas enviará la salida antes de que la frene el control de flujo?**

La respuesta observada —124 con control de congestión y 500 sin él— depende de qué ventana se agote primero. El resultado de 500 sorprende a quien esperaba 1000 celdas de ventana histórica de circuito: aquí limita antes la ventana de flujo.

## Qué debes saber para que funcione

- Se necesita un **servidor en el puerto 8080**, también usado por la batería completa de pruebas. Detén el servidor manual antes de ejecutar esa batería.
- El archivo debe superar la ventana activa. Con menos de 124 celdas (unos 60 KB), apenas se observa el efecto del control de congestión.
- Los StreamID de un mismo circuito deben ser **distintos y no nulos**.
- Si una transferencia grande acaba con `DESTROY`, verifica que el contador `SENDME` se comparta entre todos los flujos del circuito.

## Procedencia de las reglas

| En el código | En la especificación |
|---|---|
| `BEGIN`, `CONNECTED` y formato ADDRPORT | tor-spec, *Opening streams and transmitting data* |
| Motivos de `END` | tor-spec, *Closing streams* |
| Ventanas y `SENDME` | tor-spec, *Flow control* |
| `SENDME` autenticados | Propuesta 289 |
| Control de congestión y `sendme_inc` | Propuesta 324 |

