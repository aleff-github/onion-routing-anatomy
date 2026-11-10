# Laboratorio 4 — Cifrado por capas y circuito de tres saltos

| | |
|---|---|
| **Capítulo** | 10 — Cifrado por capas |
| **¿Requiere la red?** | Sí |
| **Requisitos previos** | Laboratorios 1–3 |
| **Duración** | Aproximadamente tres horas de implementación; un minuto para repetirlo |
| **Módulos previstos** | `labs/es/codigo/torlab/encryption.py`, `labs/es/codigo/torlab/circuit.py` |

## Qué demuestra

Este laboratorio muestra cómo funciona realmente la «cebolla»: una clave de cifrado y un resumen criptográfico acumulativo **por cada salto y para cada dirección**, mientras el cliente envuelve cada mensaje en tantas capas como saltos tiene el circuito. Un repetidor intermedio no sabe de antemano si el valor recibido es para él o si representa otra capa que debe retirar. Intenta reconocerlo y, si falla, reenvía el resultado.

Además, construimos un circuito real paso a paso, extendiéndolo por tres repetidores hasta una salida.

## Preparación

```bash
make -C labs/es/laboratorio start
export PYTHONPATH=labs/es/codigo
```

## Ejecutar el experimento

```bash
python3 - <<'EOF'
import time
from torlab.cells import CellCommand
from torlab.circuit import build
from torlab.laboratory import relay

circ = build([relay("003r"), relay("004r"), relay("006e")])
print("saltos:", len(circ.crypto.hops),
      "| extensiones solicitadas a la salida:", circ.exit_extensions)

# Relleno de enlace, que no aparecía en el laboratorio 1.
circ.channel.sock.settimeout(12)
seen, t = 0, time.time()
try:
    while time.time() - t < 12:
        if circ.channel.receive().command == CellCommand.PADDING:
            seen += 1
except TimeoutError:
    pass
print(f"Celdas PADDING recibidas en 12 s: {seen}")
EOF
```

## Resultado de referencia

```text
saltos: 3 | extensiones solicitadas a la salida: [(2, b'\x1f')]
Celdas PADDING recibidas en 12 s: 3
```

Los mensajes coinciden con los `print` del ejemplo localizado; las cantidades son ilustrativas.

- `build` abre el canal hacia el guardia, crea el primer salto con ntor-v3 y solicita dos extensiones. `EXTEND2` utiliza **StreamID cero**, ya que controla el circuito, no un flujo de aplicación. Se transporta mediante `RELAY_EARLY`, no `RELAY`; de ahí el mecanismo que limita las extensiones a ocho celdas de ese tipo ([laboratorio 17](Laboratorio-17-Relay-early.md)).
- En este ejemplo, el control de congestión se solicita **solo al último salto**. La respuesta de la salida `[(2, b'\x1f')]` indica `sendme_inc = 31`.
- **El relleno de enlace depende de la configuración y del tiempo.** Extender la ruta más allá del guardia puede activar las condiciones para emitir relleno; el valor de referencia es ilustrativo y no garantiza ninguna celda `PADDING` en doce segundos.

## Núcleo del laboratorio

El cifrado cebolla consiste, esencialmente, en dos bucles:

```python
def encrypt(self, msg: RelayMessage, destination: int | None = None) -> bytes:
    d = len(self.hops) - 1 if destination is None else destination
    body = self.hops[d].forward.sign(encode_relay(msg))
    for i in range(d, -1, -1):
        body = self.hops[i].forward.apply(body)
    return body

def decrypt(self, body: bytes) -> tuple[int, RelayMessage]:
    for i, hop in enumerate(self.hops):
        body = hop.backward.apply(body)
        if hop.backward.recognizes(body):
            return i, decode_relay(body)
    raise CellError("celda no reconocida por ningún salto: cerrar el circuito")
```

`recognizes` es más sutil de lo que parece. Exige que `Recognized` valga cero **y** que coincida el digest acumulativo. Si falla la verificación, el estado real del digest no debe cambiar, pues un falso positivo desincronizaría el circuito. La implementación comprueba una copia (`self.digest.copy()`) y solo la adopta cuando la verificación es correcta.

Estos fragmentos pertenecen a los métodos `ClientCircuitCrypto` y `Circuit`; los módulos completos definen las importaciones, los tipos y el estado.

## Limitación de las pruebas en memoria

`test_encryption.py` construye un circuito simulado de tres repetidores y verifica que cada salto reconozca únicamente sus propias celdas, que los intermedios vean bytes aparentemente aleatorios, que el destino detecte manipulaciones y que AES-CTR sea maleable.

Estas pruebas tienen una limitación importante: cliente y repetidores simulados utilizan **la misma implementación**. Si ambos actualizaran el digest en el mismo orden incorrecto, las pruebas podrían superarse. La comprobación más convincente es la interoperabilidad con la implementación independiente `tor`, precisamente lo que evalúa el laboratorio original.

## Verificación automática

El verificador original italiano `lab4` pertenece a `scripts/verify_labs.py`: no es un comando `lab4` independiente dentro de este entorno español. `test_encryption.py` ofrece pruebas unitarias offline con repetidores simulados, mientras que el ejemplo anterior es un experimento manual de interoperabilidad en la red privada Chutney. El relleno puede no observarse en un intervalo finito.

## Problemas conocidos

| Síntoma | Causa |
|---|---|
| `celda no reconocida por ningún salto: cerrar el circuito` | Estado del digest desincronizado, a menudo por actualizarlo incluso cuando falla el reconocimiento. |
| `PADDING cells received: 0` | El relleno es aleatorio y puede no aparecer ocasionalmente; si ocurre siempre, verifica que el circuito tenga realmente tres saltos. |
| La extensión falla con `DESTROY` | Revisar los registros y el código de motivo. Una identidad que no coincide es una posibilidad; la ausencia de Ed25519 no basta para diagnosticar el fallo. |

---

# Implementación detallada

Se han incorporado dos módulos: `labs/es/codigo/torlab/encryption.py` (el mecanismo de cifrado por capas) y `labs/es/codigo/torlab/circuit.py` (canal, CircID y saltos), conservando las API de la referencia.

## Qué guarda `Direction`

```python
POS_DIGEST = slice(5, 9)
POS_RECOGNIZED = slice(1, 3)

def _aes_ctr(key):
    return Cipher(algorithms.AES(key), modes.CTR(bytes(16))).encryptor()

def _without_digest(body):
    return body[:5] + bytes(4) + body[9:]
```

**El vector de inicialización IV es cero**, y esto no constituye un atajo. En Tor, el estado CTR continúa de una celda a la siguiente durante toda la vida del circuito, de modo que no se reinicia el flujo de clave en cada mensaje. Reinicializar el cifrador para cada celda repetiría ese flujo y debilitaría gravemente el cifrado, aunque el código pareciera funcionar.

```python
@dataclass
class Direction:
    cipher: object
    digest: "hashlib._Hash"
```

Una `Direction` agrupa dos estados que deben avanzar de manera coherente: cifrador AES-CTR y digest acumulativo. La especificación los describe por separado, pero operativamente están acoplados. Cada salto tiene dirección de ida y vuelta; un circuito de tres saltos mantiene seis objetos `Direction`.

## Cifrar y descifrar utilizan la misma primitiva

```python
def apply(self, data):
    return self.cipher.update(data)
```

En modo CTR, cifrar y descifrar equivalen a aplicar XOR con el mismo flujo de clave. Gracias a esa simetría, un repetidor intermedio puede «retirar una capa» sin emplear otra primitiva.

Esto también significa que AES-CTR es **maleable**: invertir un bit del texto cifrado invierte el bit correspondiente del texto en claro. El digest acumulativo permite detectar modificaciones de este tipo; el apéndice B lo demuestra explícitamente.

## El digest no corresponde a una sola celda

```python
def sign(self, body):
    self.digest.update(_without_digest(body))
    return body[:5] + self.digest.digest()[:4] + body[9:]
```

El digest acumulativo abarca **solo las celdas relay originadas por este salto o dirigidas a él en esa dirección**; no incluye las celdas reenviadas a otros saltos. `update` acumula el estado, por lo que cada mensaje aceptado depende de su historia anterior.

La secuencia es: poner el campo Digest a cero mediante `_without_digest`, actualizar el hash acumulativo con esa representación, tomar sus primeros cuatro bytes y escribirlos en Digest. El receptor realiza el mismo cálculo.

Consecuencia práctica: **perder o reordenar una celda relay desincroniza permanentemente el estado acumulativo**. Tor no intenta recuperar ese circuito; lo cierra.

Los circuitos ordinarios utilizan SHA-1 para este digest acumulativo, mientras que los de servicios onion utilizan SHA3-256. El empleo de SHA-1 aquí responde a esta construcción de protocolo, no a los requisitos habituales de resistencia a colisiones de un hash independiente.

## Reconocimiento: la copia que protege el circuito

```python
def recognizes(self, body):
    if body[POS_RECOGNIZED] != b"\x00\x00":
        return False
    candidate = self.digest.copy()
    candidate.update(_without_digest(body))
    if candidate.digest()[:4] != body[POS_DIGEST]:
        return False                 # falso positivo: estado intacto
    self.digest = candidate
    return True
```

Es la operación más delicada del módulo.

La primera comprobación es `Recognized`: si no vale cero, este repetidor no es el destinatario previsto y no debe tocarse el digest.

Sin embargo, dos bytes cero pueden aparecer aleatoriamente con probabilidad aproximada de una entre 65 536. El digest aporta entonces una segunda comprobación. Si se actualizara directamente su estado antes de descubrir que Digest no coincide, un falso positivo estropearía todas las verificaciones posteriores.

Con `copy()` y la adopción del estado solo tras verificar correctamente, los intentos fallidos de reconocimiento **no tienen efectos secundarios**. Ese comportamiento mantiene sincronizado el circuito.

## Los dos bucles de la cebolla

```python
def encrypt(self, msg: RelayMessage, destination: int | None = None) -> bytes:
    d = len(self.hops) - 1 if destination is None else destination
    body = self.hops[d].forward.sign(encode_relay(msg))
    for i in range(d, -1, -1):
        body = self.hops[i].forward.apply(body)
    return body

def decrypt(self, body: bytes) -> tuple[int, RelayMessage]:
    for i, hop in enumerate(self.hops):
        body = hop.backward.apply(body)
        if hop.backward.recognizes(body):
            return i, decode_relay(body)
    raise CellError("celda no reconocida por ningún salto: cerrar el circuito")
```

El tráfico de salida se firma con el digest del salto de destino y se envuelve desde la capa más interna hacia la externa. El tráfico entrante elimina capas de fuera hacia dentro e intenta reconocer el mensaje después de cada una.

`decrypt` no sabe inicialmente qué salto produjo el mensaje. Identifica al remitente retirando capas y comprobando su reconocimiento, del mismo modo que actúan los repetidores del protocolo.

## Extender un circuito

```python
def extend(self, r: RelayInfo, extensions=()) -> list[tuple[int, bytes]]:
    st, hd = ntor3_client_start(r.id_ed, r.ntor, encode_extensions(list(extensions)))
    body = extend2_body("127.0.0.1", r.port, r.id_rsa, r.id_ed, HTYPE_NTOR_V3, hd)
    self.send(RelayMessage(RelayCommand.EXTEND2, 0, body), early=True)
    hop, msg = self.receive()
    if msg.command != RelayCommand.EXTENDED2:
        raise CircuitError(f"fallo de ampliación: {RelayCommand(msg.command).name}")
    sm, k = ntor3_client_finish(st, hdata_created2(msg.data))
    self.crypto.hops.append(Hop.from_keys(CircuitKeys.from_stream(k)))
    return decode_extensions(sm)
```

Tres detalles suelen ocasionar fallos difíciles de diagnosticar:

- **StreamID cero:** `EXTEND2` controla el circuito, no un flujo de aplicación.
- **`RELAY_EARLY` y no `RELAY`:** las solicitudes de extensión usan el tipo especial de celda con una reserva limitada ([laboratorio 17](Laboratorio-17-Relay-early.md)).
- **Identidades del repetidor:** este ejemplo proporciona los identificadores RSA y Ed25519 en `EXTEND2`. La especificación no exige universalmente Ed25519 en todos los mensajes `EXTEND2`; si el repetidor conoce esa identidad por el consenso, DEBERÍA comprobarla. Su ausencia por sí sola no implica necesariamente `DESTROY`.

En este ejemplo, el control de congestión se solicita solo al salto final: la extensión `(1, b"")` se envía a la salida, no al repetidor intermedio.

## Limitación de las pruebas en memoria

`test_encryption.py` comprueba invariantes importantes, pero ambos extremos simulados comparten el código. Las pruebas de protocolo que reutilizan la misma implementación pueden no detectar errores simétricos. La interoperabilidad independiente con `tor` es, por ello, una capa esencial de validación.

## Qué debes saber para que funcione

- Las claves del circuito proceden del flujo de ntor: 20+20 bytes de digest (`Df`, `Db`) y 16+16 de claves de cifrado (`Kf`, `Kb`), **72 bytes** en total. Su orden importa.
- El **estado inicial del digest** de cada dirección se siembra con `Df` o `Db`, no con un hash vacío.
- No se puede reutilizar un objeto `Direction` entre circuitos, pues contiene el estado CTR que avanza.
- Si aparece `celda no reconocida por ningún salto: cerrar el circuito` para un mensaje que debería reconocerse, revisa todas las ramas que podrían haber avanzado indebidamente el digest acumulativo.

## Procedencia de las reglas

| En el código | En la especificación |
|---|---|
| Campos Recognized y Digest | tor-spec, *Relay cells* |
| Cálculo del digest | tor-spec, *Calculating the 'Digest' field* |
| Enrutamiento de mensajes relay | tor-spec, *Routing relay cells* |
| Claves del circuito | tor-spec, *Setting circuit keys* |
| EXTEND2 y especificadores de enlace | tor-spec, *Creating circuits* |

