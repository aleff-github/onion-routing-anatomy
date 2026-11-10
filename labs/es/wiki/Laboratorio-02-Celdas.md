# Laboratorio 2 — Codificar y descodificar celdas

| | |
|---|---|
| **Capítulo** | 8 — Celdas: el formato básico |
| **¿Requiere la red?** | No |
| **Requisitos previos** | Python 3.11 o posterior |
| **Duración** | De una a dos horas de implementación; aproximadamente dos minutos para repetirlo |
| **Archivos disponibles** | `labs/es/codigo/torlab/cells.py`, `labs/es/codigo/torlab/test/test_cells.py` |

## Qué demuestra

Los **514 bytes** corresponden a celdas fijas con protocolo de enlace 4 o superior; la versión 3 usa un CircID de dos bytes y celdas de 512 bytes.

Una celda Tor tiene una estructura sencilla y rígida: cuatro bytes de CircID, uno de comando y un cuerpo de 509 bytes: **514 bytes en total**, con independencia de los datos que transporta. Esa uniformidad impide que la longitud revele directamente el contenido. Las celdas de longitud variable (`VERSIONS` y todos los comandos >= 128) son la excepción. `VERSIONS` siempre utiliza un CircID de dos bytes, ya que se intercambia antes de negociar la versión del protocolo de enlace.

## Preparación

No necesitas nada fuera del código del repositorio:

```bash
cd /ruta/al/repositorio
export PYTHONPATH=labs/es/codigo
```

## Ejecutar el experimento

```bash
python3 - <<'EOF'
from torlab.cells import *

# 1. Celda de longitud fija.
c = Cell(0x80000001, CellCommand.RELAY, b"\x01" * 509)
g = encode(c, 4)
print("longitud:", len(g), "| primeros 8 bytes:", g[:8].hex())

# 2. Descodificar: devolver la celda y los bytes restantes.
decoded_cell, remaining = decode(g, 4)
print("descodificada:", hex(decoded_cell.circ_id),
      CellCommand(decoded_cell.command).name, "| restantes:", len(remaining))

# 3. Celda de longitud variable.
print("VERSIONS:", encode(Cell(0, CellCommand.VERSIONS, b"\x00\x04\x00\x05"), 4).hex())

# 4. Mensaje relay dentro del cuerpo de una celda.
m = RelayMessage(RelayCommand.BEGIN, 1, b"127.0.0.1:80\x00")
r = encode_relay(m)
print("mensaje relay:", len(r), "bytes | cabecera:", r[:11].hex())
rit = decode_relay(r)
print("descodificado:", RelayCommand(rit.command).name, rit.stream_id, rit.data)
EOF
```

## Resultado del experimento de referencia

```text
length: 514 | first 8 bytes: 8000000103010101
decoded: 0x80000001 RELAY | remaining: 0
VERSIONS: 000007000400040005
relay message: 509 byte | header: 010000000100000000000d
decoded: BEGIN 1 b'127.0.0.1:80\x00'
```

Estas líneas son la salida inglesa original. Los textos de `print` del código anterior están traducidos, por lo que **no se reproducirán literalmente las palabras inglesas**; los bytes, identificadores y longitudes deben coincidir.

Interpretación:

- `8000000103` representa CircID `0x80000001` (el bit más significativo vale uno porque nosotros iniciamos el circuito y el canal), seguido del comando `3` (`RELAY`).
- La celda `VERSIONS` consiste en `0000` (CircID de **dos bytes**) + `07` (comando) + `0004` (longitud) + `0004 0005` (versiones ofrecidas, 4 y 5).
- La cabecera del mensaje relay contiene `01` (`BEGIN`), `0000` (`Recognized`), `0001` (StreamID), `00000000` (Digest todavía vacío; se rellenará en el laboratorio 4) y `000d` (13 bytes de datos).

`Cell.command` y `RelayMessage.command` son enteros. Para mostrar sus nombres simbólicos, conviértelos con `CellCommand(...)` y `RelayCommand(...)`.

## Verificación automática

La orden prevista para las siete pruebas independientes de la red es:

```bash
PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test/test_cells.py
```

Las siete pruebas abarcan longitudes 512/514, VERSIONS, entradas fragmentadas, negociación, aceptación de `DESTROY` con motivo 0 **y rechazo cuando CircID es 0**, un máximo de 498 bytes relay y su relleno.

La función histórica `lab2` vive en `scripts/verify_labs.py` de la edición italiana y no es un comando español independiente. La orden anterior ejecuta las pruebas `test_cells.py` españolas, no los veinte laboratorios.

## Problemas conocidos

No se registraron problemas específicos. La prueba no necesita red ni dependencias externas adicionales: si falla, comienza comprobando la instalación de Python y los archivos del repositorio.

---

# Implementación detallada

Todo el laboratorio se concentra en `labs/es/codigo/torlab/cells.py`, de unas 220 líneas en la edición de referencia. Los laboratorios posteriores dependen de este módulo. Un error aquí podría manifestarse tres experimentos después como un circuito que un repetidor cierra sin explicar bien la causa.

Los fragmentos siguientes proceden del módulo `cells.py` completo; las importaciones y otras definiciones se encuentran en el archivo original.

## Constantes

```python
CELL_BODY_LEN = 509          # bytes del cuerpo de una celda de longitud fija
RELAY_HEADER_LEN = 11        # cabecera del mensaje relay
RELAY_DATA_MAX = CELL_BODY_LEN - RELAY_HEADER_LEN   # 498
```

`RELAY_DATA_MAX` no es una constante literal copiada de la especificación: es la **consecuencia** de las otras dos longitudes. Escribir la resta, en lugar de fijar `498`, conserva la relación visible si cambia el formato. No es una posibilidad meramente teórica: el cifrado relay CGO (propuesta 359, presente en el código de tor) utiliza otra cabecera y la propuesta 340 separaría por completo mensajes y celdas.

Los comandos se representan con `IntEnum`, no con `Enum`. En un protocolo binario deben poder compararse y empaquetarse como enteros (`bytes([cell.command])`), sin perder nombres legibles.

```python
def circid_len(version):
    return 2 if version < 4 else 4

def is_variable_length(command):
    return command == CellCommand.VERSIONS or command >= 128
```

La anchura del CircID depende de la versión negociada: dos bytes hasta la versión 3 y cuatro a partir de la 4. Encapsular esa regla en una función evita dispersar números mágicos por el módulo.

La regla de `>= 128` procede del protocolo: el bit superior del comando señala longitud variable. `VERSIONS`, comando 7, es la excepción histórica porque es anterior a esa convención.

## `encode`

```python
def encode(cell: Cell, version: int) -> bytes:
    """Serializa una celda con la versión del protocolo de enlace indicada.

    VERSIONS siempre utiliza la versión 0 (CircID de 2 bytes), porque
    al enviarla todavía no se ha negociado la versión del enlace.
    """
    if cell.command == CellCommand.VERSIONS:
        version = 0
    n = circid_len(version)
    if not 0 <= cell.circ_id < 1 << (8 * n):
        raise CellError(f"CircID {cell.circ_id:#x} no cabe en {n} bytes")
    header = cell.circ_id.to_bytes(n, "big") + bytes([cell.command])
    if is_variable_length(cell.command):
        if len(cell.body) > 0xFFFF:
            raise CellError("cuerpo demasiado largo para una celda de longitud variable")
        return header + struct.pack(">H", len(cell.body)) + cell.body
    if len(cell.body) > CELL_BODY_LEN:
        raise CellError(f"cuerpo de {len(cell.body)} bytes > {CELL_BODY_LEN}")
    # Completar con ceros hasta CELL_BODY_LEN (tor-spec, body-padding).
    return header + cell.body.ljust(CELL_BODY_LEN, b"\x00")
```

Las dos primeras líneas contienen el caso que sorprende a muchos lectores. `VERSIONS` se intercambia *antes* de acordar la versión de enlace, por lo que su formato no puede depender de ella. Forzar `version = 0` produce un CircID de dos bytes, como exige la especificación. Es la única celda cuyo formato debe determinarse con independencia de la negociación; de otro modo no podríamos negociar.

`"big"` indica orden de bytes de red, empleado por Tor para sus enteros. Validar el rango del CircID es técnicamente redundante porque `to_bytes` lanzaría `OverflowError`, pero el error propio explica qué valor ha fallado y cuántos bytes cabían, algo útil al aprender.

Las dos familias de celdas divergen aquí:

- **Longitud variable:** se escriben los dos bytes de `Length` y después exactamente el cuerpo proporcionado. No se necesita relleno fijo porque la longitud es explícita.
- **Longitud fija:** el cuerpo se completa con ceros hasta **509 bytes**. La especificación lo exige y los receptores ignoran los bytes añadidos.

> El relleno de la celda fija pertenece al enlace: el extremo TLS inmediato lo ve al descifrar, pero no un observador externo. El relleno relay queda protegido por las capas onion hasta el salto que reconoce y descifra el mensaje.

## `decode`

**Al recibir `VERSIONS` usa la versión 0:** antes de negociar, llama a `decode(buffer, 0)` para leer su CircID de dos bytes. Solo después utiliza `decode(buffer, negotiated_version)` con las demás celdas; pasar 4 antes de tiempo interpretaría mal la cabecera.

```python
def decode(buffer: bytes, version: int) -> tuple[Cell, bytes] | None:
    """Extrae la primera celda de `buffer`.

    Devuelve (celda, bytes_restantes), o None si todavía no hay una celda
    completa: TLS puede entregar fragmentos de tamaño arbitrario.
    """
    n = circid_len(version)
    if len(buffer) < n + 1:
        return None
    circ_id = int.from_bytes(buffer[:n], "big")
    command = buffer[n]
    if is_variable_length(command):
        if len(buffer) < n + 3:
            return None
        (length,) = struct.unpack(">H", buffer[n + 1:n + 3])
        end = n + 3 + length
        body_start = n + 3
    else:
        end = n + 1 + CELL_BODY_LEN
        body_start = n + 1
    if len(buffer) < end:
        return None
    return Cell(circ_id, command, buffer[body_start:end]), buffer[end:]
```

La función se llama cada vez que llegan bytes de un socket, incluso sin saber si ya se recibió una celda completa. Por ello incluye **tres** comprobaciones de integridad de datos, justo donde suelen fallar los analizadores ingenuos:

1. Sin CircID ni comando, no sabemos qué formato se utiliza.
2. Una celda variable requiere dos bytes más para conocer su longitud.
3. Finalmente debe haber llegado el cuerpo completo.

Devolver `None` significa «vuelve a llamarme cuando haya más bytes», no «error de protocolo». Así, el código llamador es sencillo:

```python
while True:
    result = decode(buffer, version)
    if result is None:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed before a complete cell")
        buffer += chunk
        continue
    cell, buffer = result
    ...
```

Los límites entre registros TLS y celdas son independientes; una lectura puede contener fragmentos o varias celdas. En 16 KiB caben hasta 31 celdas de 514 bytes, pero no es una agrupación obligatoria.

El cliente educativo utiliza buffers `bytes` inmutables y obtiene el resto mediante cortes de secuencia. Una implementación de producción podría usar un buffer circular para evitar copias repetidas, diferencia que importa con el rendimiento de un repetidor real.

## `negotiate_version`

```python
def negotiate_version(ours: list[int], received_body: bytes) -> int:
    """Selecciona la versión más alta admitida por ambos extremos (tor-spec, VERSIONS-cells)."""
    if len(received_body) % 2:
        raise CellError("VERSIONS contiene un número impar de bytes")
    theirs = {v for (v,) in struct.iter_unpack(">H", received_body)}
    common = set(ours) & theirs
    if not common:
        raise CellError("no existe una versión de enlace compartida")
    return max(common)
```

Un cuerpo de longitud impar no puede ser una lista de enteros de dos bytes, de modo que se rechaza en vez de adivinarlo. Se calcula la intersección de ambas listas y se elige el valor común **más alto**, conforme a la regla del protocolo.

**Corrección documental respecto al inglés:** en el fragmento original la firma utilizaba el nombre `mie` mientras el cuerpo leía `ours`, lo que produciría `NameError` si se copiara literalmente. Aquí se usa `ours` de forma consistente. Esto no implica ninguna modificación comprobada del módulo ejecutable.

¿Puede un intermediario producir un **downgrade**, eliminando versiones recientes de las listas? Esta función no puede detectarlo por sí sola. La protección depende del canal circundante:

- El intercambio transcurre dentro de TLS, y el [laboratorio 1](Laboratorio-01-Canal.md) lo vincula a la identidad del repetidor mediante `CERTS`.
- Cuando quien inicia el canal es otro repetidor y se autentica, el resumen `AUTHENTICATE` cubre **todos** los bytes intercambiados, incluido `VERSIONS`. Por tanto, detectaríamos una alteración.

## `encode_relay`

```python
def encode_relay(msg: RelayMessage, random_bytes=os.urandom) -> bytes:
    """Genera el cuerpo en claro de 509 bytes de una celda RELAY.

    Relleno: 4 bytes cero seguidos de bytes aleatorios (tor-spec, relay-cell-padding).
    El digest se calcula aparte (capítulo 10); aquí se usa el valor de `msg`.
    """
    if len(msg.data) > RELAY_DATA_MAX:
        raise CellError(f"la celda admite como máximo {RELAY_DATA_MAX} bytes de datos")
    header = struct.pack(">BHH4sH", msg.command, msg.recognized,
                               msg.stream_id, msg.digest, len(msg.data))
    space = CELL_BODY_LEN - RELAY_HEADER_LEN - len(msg.data)
    padding = b"\x00" * min(4, space) + random_bytes(max(0, space - 4))
    return header + msg.data + padding
```

Una sola llamada a `struct.pack` serializa los cinco campos de cabecera. El formato `">BHH4sH"` se lee de izquierda a derecha como el esquema del capítulo 8: comando (un byte), `Recognized` (dos), StreamID (dos), Digest (cuatro bytes sin interpretar, por eso `4s`) y `Length` (dos). Total: 11 bytes, exactamente `RELAY_HEADER_LEN`.

La especificación **recomienda** (SHOULD) hasta cuatro bytes cero, seguidos de valores aleatorios si queda espacio; si sobra menos de cuatro bytes, todos son cero. El relleno no demuestra reconocimiento: se comprueban `Recognized` y `Digest`.

| | Celdas de longitud fija | Mensajes relay |
|---|---|---|
| Relleno | Solo ceros | Hasta 4 ceros y después aleatorios, si queda espacio |
| Quién lo ve en claro | Extremo TLS inmediato, no un observador externo | Salto que reconoce y descifra el mensaje relay |
| Propósito | Completar el tamaño fijo del cuerpo | Hacer impredecible la parte no utilizada del cuerpo relay |

Si el relleno relay estuviera compuesto solo de ceros, un adversario capaz de adivinar la carga útil conocería el resto del cuerpo, con efectos negativos en la construcción de `SENDME` autenticados de la propuesta 289 ([laboratorio 5](Laboratorio-05-Flujos.md)). La especificación **recomienda** (SHOULD) hasta cuatro bytes cero, seguidos de valores aleatorios si queda espacio; si sobra menos de cuatro bytes, todos son cero. El relleno no demuestra reconocimiento: se comprueban `Recognized` y `Digest`.

El parámetro `random_bytes` existe únicamente para las pruebas, que pueden sustituir los bytes aleatorios por valores previsibles. Sin esta inyección de dependencias, las pruebas solo podrían comprobar la longitud. Se trata de una regla de diseño utilizada en todo el repositorio: **inyecta la no determinación en vez de ocultarla dentro de la implementación**.

Para la comprobación de reconocimiento y digest dentro del cifrado onion, consulta el [laboratorio 4](Laboratorio-04-Cifrado.md).

## Procedencia de los formatos

| En el código | En spec.torproject.org |
|---|---|
| Longitudes y formatos de celdas | tor-spec, *Cells (messages on channels)* |
| Relleno con ceros | tor-spec, *Padding fixed-length cell bodies* |
| `VERSIONS` y negociación | tor-spec, *Negotiating versions with VERSIONS cells* |
| Cabecera de mensajes relay | tor-spec, *Relay cells* |
| Cuatro ceros y bytes aleatorios | tor-spec, *Relay cells* (motivación: propuesta 289) |
| Listas de comandos | Tablas de tor-spec en *Cells* y *Relay cells* |

