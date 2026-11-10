# Laboratorio 3 — Intercambios criptográficos de circuitos: ntor, ntor-v3 y CREATE_FAST

| | |
|---|---|
| **Capítulo** | 9 — Construir un circuito |
| **¿Requiere la red?** | Sí |
| **Requisitos previos** | Laboratorios 1 y 2; `cryptography`, `hashlib` (SHA-3 y SHAKE) |
| **Duración** | De tres a cuatro horas de implementación; alrededor de un minuto para repetirlo |
| **Módulo disponible** | `labs/es/codigo/torlab/ntor.py` |

## Qué demuestra

Se puede implementar un intercambio criptográfico directamente a partir de la especificación y conseguir que interopere con otra implementación independiente: una de las comprobaciones más convincentes. También muestra cómo responde un repetidor cuando falla una validación. Cambiar un solo bit del MAC produce `DESTROY` con razón `PROTOCOL`, no un mensaje de error detallado.

Se estudian cuatro variantes: ntor-v3 sin extensiones, ntor-v3 negociando control de congestión, ntor clásico y `CREATE_FAST`.

## Preparación

Comandos:

```bash
make -C labs/es/laboratorio start
export PYTHONPATH=labs/es/codigo
```

`torlab.laboratory.relay("003r")` cargará la identidad Ed25519 y `ntor-onion-key` del repetidor a partir de los archivos de la red privada y de los microdescriptores del cliente, la misma clase de datos que obtiene un cliente real del directorio.

## Ejecutar el experimento

```bash
python3 - <<'EOF'
from torlab.channel import open_channel
from torlab.cells import Cell, CellCommand, describe
from torlab.laboratory import relay
from torlab.ntor import *

g = relay("003r")
c = open_channel("127.0.0.1", g.port, expected_identity=g.id_ed)

def create(circ, htype, hdata):
    c.send(Cell(circ, CellCommand.CREATE2, create2_body(htype, hdata)))
    r = c.receive()
    print("<-", describe(r, c.version))
    return r

# 1. ntor-v3 sin extensiones.
st, hd = ntor3_client_start(g.id_ed, g.ntor, encode_extensions([]))
r = create(0x80000001, HTYPE_NTOR_V3, hd)
sm, _ = ntor3_client_finish(st, hdata_created2(r.body))
print("   ntor-v3 correcto, mensaje del repetidor:", decode_extensions(sm))

# 2. ntor-v3 solicitando control de congestión.
st, hd = ntor3_client_start(g.id_ed, g.ntor, encode_extensions([(1, b"")]))
r = create(0x80000002, HTYPE_NTOR_V3, hd)
sm, _ = ntor3_client_finish(st, hdata_created2(r.body))
print("   ntor-v3 con CC_FIELD_REQUEST correcto, respuesta:", decode_extensions(sm))

# 3. ntor clásico.
st, hd = ntor_client_start(g.id_rsa, g.ntor)
ntor_client_finish(st, hdata_created2(create(0x80000003, HTYPE_NTOR, hd).body))
print("   ntor correcto")

# 4. CREATE_FAST (solo circuitos de un salto, pues depende de TLS).
x, body = create_fast_client()
c.send(Cell(0x80000004, CellCommand.CREATE_FAST, body))
r = c.receive(); print("<-", describe(r, c.version))
complete_create_fast(x, r.body); print("   CREATE_FAST correcto")

# 5. Modificar deliberadamente un bit del MAC.
st, hd = ntor3_client_start(g.id_ed, g.ntor, encode_extensions([]))
r = create(0x80000005, HTYPE_NTOR_V3, hd[:-1] + bytes([hd[-1] ^ 1]))
assert r.command == CellCommand.DESTROY and r.body[0] == 1
print("   razón:", r.body[0], "(MAC modificado)")

# 6. Pedir CGO sin control de congestión.
st, hd = ntor3_client_start(g.id_ed, g.ntor, encode_extensions([(3, b"\x02\x06")]))
r = create(0x80000006, HTYPE_NTOR_V3, hd)
assert r.command == CellCommand.DESTROY and r.body[0] == 1
print("   razón:", r.body[0], "(CGO solicitado sin control de congestión)")
EOF
```

## Resultado histórico del laboratorio original

```text
<- CircID=0x80000001 CREATED2 cuerpo=509 bytes
   ntor-v3 ok, relay message: []
<- CircID=0x80000002 CREATED2 cuerpo=509 bytes
   ntor-v3 with CC_FIELD_REQUEST ok, response: [(2, b'\x1f')]
<- CircID=0x80000003 CREATED2 cuerpo=509 bytes
   ntor ok
<- CircID=0x80000004 CREATED_FAST cuerpo=509 bytes
   CREATE_FAST ok
<- CircID=0x80000005 DESTROY cuerpo=509 bytes
   reason: 1 (modified MAC)
<- CircID=0x80000006 DESTROY cuerpo=509 bytes
   reason: 1 (CGO requested without congestion control)
```

Se conserva la salida inglesa como referencia; las cadenas `print` del ejemplo español están traducidas y, por tanto, **no tendrán el mismo texto literal**, aunque los tipos de celda, cuerpos y códigos de razón deben corresponder.

Interpretación:

- La extensión CC_FIELD_RESPONSE (tipo 2) devuelve `sendme_inc = 0x1f = 31`: el **intervalo de celdas DATA entre confirmaciones SENDME** al negociar control de congestión. La propuesta 324 eligió 31, entre otras razones, por su relación con la capacidad aproximada de un registro TLS máximo, pero **no determina el tamaño de un registro TLS**. Este parámetro también aparece en el [laboratorio 5](Laboratorio-05-Flujos.md) y en el descriptor onion del [laboratorio 8](Laboratorio-08-Onion.md).
- **Razón 1 significa `PROTOCOL`.** Aquí el repetidor puede comunicar el motivo local porque el error ocurrió en él. Cuando retransmite un `DESTROY` de otro nodo, no debe revelar dónde ocurrió el fallo dentro del circuito.
- El último caso demuestra la dependencia entre extensiones: CGO requiere control de congestión. Solicitar CGO aisladamente es inválido.
- En la salida histórica de esta red privada no aparecieron celdas `PADDING`. Su envío depende de la negociación, la actividad de circuitos y los parámetros; un resultado concreto no demuestra su ausencia obligatoria.

## Por qué importan los vectores de prueba

No basta con que dos implementaciones consigan comunicarse: podrían compartir el mismo error. `test_ntor.py` reproduce los **vectores oficiales** de la propuesta 332 para ntor-v3 y de la 216 para HKDF de ntor. Las entradas, incluso las claves supuestamente aleatorias, son fijas y las salidas deben coincidir byte por byte. Otras pruebas exigen que modificar `AUTH` o la cadena `VER` haga fallar el intercambio.

`hmac.compare_digest` evita terminar claramente en el primer byte diferente al comparar valores de igual tipo y longitud; no garantiza por sí solo que toda la aplicación funcione en tiempo constante.

## Verificación automática

La función `lab3` del verificador italiano `scripts/verify_labs.py` cubre seis escenarios de red; no es un comando independiente de la edición española. Para los vectores y pruebas negativas offline utiliza `PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test/test_ntor.py`; ejecuta los seis ejemplos anteriores por separado en la red privada Chutney.

## Problemas conocidos

| Síntoma | Causa |
|---|---|
| `LookupError: no hay microdescriptor para 003r` | El cliente aún no descargó los microdescriptores. Espera un minuto después de iniciar la red o comprueba el arranque. |
| `CREATE2` devuelve `DESTROY` (comando 4) | El circuito falló: posibles causas son handshake inválido, extensión no admitida, claves antiguas o estado transitorio del repetidor. Examina el código de motivo y los registros de la red privada antes de reintentar. |
| `HandshakeError: AUTH de ntor-v3 no válido` | Utilizas claves de otro repetidor o de una inicialización anterior de la red. |

---

# Implementación detallada

`labs/es/codigo/torlab/ntor.py` conserva la implementación de referencia localizada, de unas 240 líneas. Conviene escribirlo con la especificación abierta y validarlo mediante vectores oficiales. En criptografía, «funciona» no significa automáticamente «es correcto».

Los fragmentos proceden de los archivos completos `ntor.py` y `test_ntor.py` de esta edición; los tipos, constantes e importaciones están definidos allí. La transcripción es histórica, no una nueva ejecución validada.

## Primitivas

```python
NTOR3_PROTOID = b"ntor3-curve25519-sha3_256-1"

def _t(name: str) -> bytes:
    return NTOR3_PROTOID + b":" + name.encode()

def _encap(s: bytes) -> bytes:
    return struct.pack(">Q", len(s)) + s

def _h3(s: bytes, t: bytes) -> bytes:
    return hashlib.sha3_256(_encap(t) + s).digest()

def _mac3(k: bytes, msg: bytes, t: bytes) -> bytes:
    return hashlib.sha3_256(_encap(t) + _encap(k) + msg).digest()

def _kdf3(s: bytes, t: bytes, length: int) -> bytes:
    return hashlib.shake_256(_encap(t) + s).digest(length)
```

Estas líneas implementan las fórmulas del apéndice A.1 de la propuesta 332 e ilustran tres ideas.

**Separación de dominios.** `PROTOID` participa en cada cálculo y evita confundir un valor producido en este protocolo con otro de un protocolo distinto que use la misma primitiva y quizá las mismas claves.

**Identificadores de propósito o tweaks.** Una construcción hash se separa en funciones específicas: `kdf_phase1`, `msg_mac`, `key_seed`, `verify`, `kdf_final` y `auth_final`. Sin separar explícitamente estos usos, podrían confundirse valores derivados para funciones diferentes.

**Codificación estructurada.** `_encap` antepone a cada cadena de bytes su longitud, codificada en ocho bytes, para que la concatenación sea **inequívoca**. Sin longitudes, las parejas (`"ab"`, `"c"`) y (`"a"`, `"bc"`) producirían `"abc"`. Una codificación criptográfica correcta debe incluir estructura y contenido.

Un detalle fundamental: en `_mac3` se encapsula la *clave*, pero no el mensaje. Así lo define exactamente la propuesta. Intentar hacerlo «más uniforme» encapsulando ambos rompería la interoperabilidad, algo que los vectores revelarían inmediatamente.

## Fase 1: mensaje del cliente

```python
def ntor3_client_start(ID: bytes, B: bytes, message: bytes, ver: bytes = CIRCUIT_VERIFICATION,
                        x: bytes | None = None) -> tuple[Ntor3State, bytes]:
    """CREATE2 HDATA para ntor-v3: ID (32) | B (32) | X (32) | MSG cifrado | MAC (32)."""
    sk, X = x25519_generate(x)
    Bx = x25519_dh(sk, B)
    fase1 = _kdf3(Bx + ID + X + B + NTOR3_PROTOID + _encap(ver), _t("kdf_phase1"), 64)
    enc_k1, mac_k1 = fase1[:32], fase1[32:]
    mensaje_cifrado = aes_ctr(enc_k1, message)          # AES-256-CTR
    mac = _mac3(mac_k1, ID + B + X + mensaje_cifrado, _t("msg_mac"))
    return Ntor3State(sk, X, B, ID, Bx, mac, ver), ID + B + X + mensaje_cifrado + mac
```

El cliente genera un par efímero (`sk`, `X`) y calcula **`Bx`**, un valor Diffie–Hellman que combina su clave privada efímera con la **clave estática** `ntor-onion-key` del repetidor. Deriva de él dos claves: una para cifrar su mensaje de intercambio y otra para autenticarlo.

> **La primera fase, por sí sola, no ofrece secreto hacia adelante para el mensaje cifrado del cliente.** `Bx` depende de la clave estática del repetidor; si esta se compromete posteriormente, podrían descifrarse mensajes de fase 1 capturados con anterioridad. El protocolo coloca por ello opciones negociadas en `CM`, no secretos duraderos de aplicación. El material de clave del circuito obtiene secreto hacia adelante en la fase 2.

El argumento opcional `x` existe solo para pruebas; permite fijar una clave que normalmente sería aleatoria y reproducir exactamente los vectores oficiales.

La cadena `ver` predeterminada es `b"circuit extend"` para extender circuitos. Se incorpora a la derivación; cambiar un byte modifica las claves. Así se impide reutilizar transcripciones de intercambio creadas para un contexto en otro protocolo.

## Fase 2: respuesta del repetidor

```python
def ntor3_client_finish(st: Ntor3State, response: bytes,
                      length=CIRCUIT_KEY_MATERIAL_LEN) -> tuple[bytes, bytes]:
    """Respuesta = Y (32) | AUTH (32) | MSG. Devuelve (mensaje del repetidor, flujo de claves)."""
    Y, auth, msg = response[:32], response[32:64], response[64:]
    secret_input = (x25519_dh(st.x, Y) + st.Bx + st.ID + st.B + st.X + Y
                    + NTOR3_PROTOID + _encap(st.ver))
    key_seed = _h3(secret_input, _t("key_seed"))
    verify = _h3(secret_input, _t("verify"))
    auth_input = (verify + st.ID + st.B + Y + st.X + st.mac + _encap(msg)
                  + NTOR3_PROTOID + b"Server")
    if not hmac.compare_digest(_h3(auth_input, _t("auth_final")), auth):
        raise HandshakeError("AUTH de ntor-v3 no válido")
    stream = _kdf3(key_seed, _t("kdf_final"), 32 + length)
    return aes_ctr(stream[:32], msg), stream[32:]
```

`secret_input` combina **dos** valores Diffie–Hellman, cada uno con su función:

| Valor | Qué combina | Para qué sirve |
|---|---|---|
| `Yx` (`x25519_dh(st.x, Y)`) | Clave efímera del cliente × clave efímera del repetidor | **Secreto hacia adelante:** las claves a largo plazo no bastan para reconstruirlo |
| `Bx` | Clave efímera del cliente × clave estática del repetidor | **Autenticación:** solo el repetidor con la clave privada estática correspondiente puede derivarlo |

Este es el núcleo de ntor: un intercambio ofrece ambas propiedades. Eliminar `Bx` eliminaría la autenticación del repetidor; eliminar `Yx` eliminaría el secreto hacia adelante.

`hmac.compare_digest` evita una comparación que termine claramente en el primer byte distinto y es la primitiva adecuada para verificar valores de autenticación.

El flujo final de claves es más largo que las claves del circuito. Los primeros 32 bytes descifran el mensaje de respuesta del repetidor; los siguientes 72 se convierten en `Df`, `Db`, `Kf` y `Kb`, que utiliza el [laboratorio 4](Laboratorio-04-Cifrado.md) para proteger las celdas relay.

## Vectores oficiales como validación

Los vectores aportan evidencia reproducible de coincidencia con los ejemplos oficiales, pero no prueban por sí solos la seguridad o corrección de todas las rutas de ejecución.

```python
def test_ntor3_vectors_proposal_332():
    st, hdata = ntor3_client_start(h(V["ID"]), h(V["B"]), h(V["CM"]), ver=h(V["VER"]), x=h(V["x"]))
    assert hdata.hex() == V["client"]
    sm, key_stream = ntor3_client_finish(st, h(V["server"]), length=256)
    assert sm == h(V["SM"])
    assert key_stream[:32].hex() == V["keystream_start"]
```

Las entradas deben ser fijas y las salidas coincidir byte por byte. `test_ntor.py` reproduce el vector completo ntor-v3 de la propuesta 332 y los de ntor HKDF de la propuesta 216. Otras pruebas cambian deliberadamente `AUTH` y `ver` para exigir fallo: un verificador que aceptase todo podría aprobar el vector positivo.

## Las cuatro variantes y su utilidad

| Intercambio | Cuándo se utiliza | Observaciones |
|---|---|---|
| **ntor-v3** | Predeterminado actual, si se admite | Puede negociar opciones en un mensaje cifrado |
| **ntor** | Repetidores sin la capacidad relay más reciente | No tiene mensaje de negociación, solo acuerdo de claves |
| **CREATE_FAST** | Solo circuitos **de un salto** | No usa DH independiente, depende del canal TLS |
| TAP | Nunca en el tor actual | Retirado en tor 0.4.9.1-alpha |

`CREATE_FAST` es adecuado solo cuando el primer salto también es el último, como en ciertos circuitos de directorio, pues no introduce un intercambio Diffie–Hellman independiente del TLS subyacente. No debe sustituir a ntor en circuitos ordinarios de varios saltos.

## Qué debes saber para que funcione

- **Claves de repetidor:** `torlab.laboratory.relay("003r")` cargará identidad Ed25519 y `ntor-onion-key` desde los archivos de nodo y microdescriptores. Espera después del arranque si aún no se descargaron.
- **CircID diferente en cada prueba.** Reutilizar uno que ya está abierto produce `DESTROY`.
- Quien inicia el canal debe establecer el bit más significativo del CircID: `0x80000001`, no `0x00000001`, para evitar colisiones entre ambos extremos.
- Terminar el intercambio no crea un flujo de datos. Después de `CREATED2` hay un circuito de un salto y material de clave; el [laboratorio 4](Laboratorio-04-Cifrado.md) añade cifrado relay y extensión.

## Procedencia de las fórmulas

| En el código | Fuente |
|---|---|
| Primitivas, tweaks y ENCAP | Propuesta 332, apéndice A.1 |
| Fases 1 y 2 del cliente | Propuesta 332, *Client operation* |
| Vectores de prueba | Propuesta 332 (ntor-v3) y propuesta 216 (ntor) |
| Formato CREATE2/CREATED2 | tor-spec, *CREATE and CREATED cells* |
| Negociación de extensiones | tor-spec, *Sending extensions in the circuit extension handshake* |

