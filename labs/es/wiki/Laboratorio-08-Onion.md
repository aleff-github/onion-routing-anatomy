# Laboratorio 8 — Localizar y leer un descriptor de servicio onion

| | |
|---|---|
| **Capítulo** | 14 — Servicios onion |
| **¿Requiere la red?** | Sí |
| **Requisitos previos** | Laboratorios 1–6 |
| **Duración** | Unas cuatro horas de implementación; dos minutos para repetirlo |
| **Módulo** | `labs/es/codigo/torlab/onion.py` |

## Qué demuestra

**Alcance del experimento:** la descarga utiliza el último repetidor indicado explícitamente por el llamador (`006e`). `download_descriptor()` **no calcula ni elige el HSDir responsable**. Los algoritmos del anillo existen por separado; una descarga satisfactoria no los valida. Tampoco se implementa la gestión de credenciales de descubrimiento restringido.

La dirección onion **codifica** la clave pública Ed25519 de identidad, un checksum y la versión. Un HSDir que solo conoce la clave cegada no recupera directamente la identidad a largo plazo; pero quien ya conoce la dirección puede derivar las claves cegadas de sus períodos. No equivale a ocultarse frente a observadores que conocen la dirección.

Una dirección `.onion` v3 **se deriva de una clave pública**. A partir de ella, un cliente puede calcular la clave cegada correspondiente al período actual, determinar la posición del servicio en el anillo de HSDir, descargar el descriptor, verificar su firma y descifrar las capas hasta descubrir los puntos de introducción.

La clave cegada impide que un HSDir conozca de inmediato la identidad a largo plazo del servicio cuyo descriptor almacena. Cambia con cada período; sin conocer la dirección onion, un observador no puede relacionarla directamente con esa identidad.

## Preparación

Comandos previstos para la edición española:

```bash
make -C labs/es/laboratorio start
export PYTHONPATH=labs/es/codigo
```

El servicio onion de la red privada es `009h` y su dirección se guarda en `labs/es/laboratorio/net/nodes/009h/hidden_service/hostname`.

## Ejecutar el experimento

```bash
python3 - <<'EOF'
import calendar, time
from torlab.circuit import build, CircuitError
from torlab.laboratory import relay, NODES
from torlab.directory import parse_consensus, download
from torlab.onion import *

address = (NODES / "009h/hidden_service/hostname").read_text().strip()
print("dirección:", address)
A = key_from_address(address)
print("reconstruida desde la dirección:", onion_address(A) == address)

c = parse_consensus(download(build([relay("000a")], cc=False),
                              "/tor/status-vote/current/consensus-microdesc", 1).decode())
ts = lambda k: calendar.timegm(time.strptime(" ".join(c.header[k]), "%Y-%m-%d %H:%M:%S"))
t = time_period_info(ts("valid-after"), ts("fresh-until") - ts("valid-after"),
                     test_network=True)
print("período:", t.period, "duración (min):", t.duration_minutes)
Ap = blinded_key(A, t.period, t.duration_minutes)
print("clave cegada:", Ap.hex()[:8] + "...")

# 1. Control negativo: circuito de un solo salto.
try:
    download_descriptor(Ap, [relay("006e")])
    raise AssertionError("la solicitud de descriptor de un solo salto tuvo éxito inesperado")
except CircuitError as e:
    print("circuito de un salto ->", e)

# 2. Tres saltos, como utiliza un cliente real.
desc = parse_descriptor(
    download_descriptor(Ap, [relay("003r"), relay("004r"), relay("006e")]), A, Ap)
print(f"validez {desc.duration_minutes}, revisión {desc.revision}, "
      f"puntos de introducción {len(desc.introduction_points)}")
for line in desc.inner_layer.splitlines()[:6]:
    print("  ", line[:66])
EOF
```

## Resultado original de referencia

**Salida histórica ilustrativa:** dirección, clave cegada, período, revisión y respuesta HTTP pueden variar.

El HTTP `503` de la petición a un solo salto es el resultado esperado en esta red privada, pero el texto exacto no es universal entre versiones o directorios. No debe deducirse del código que todos los HSDir devolverán esa misma cadena.

```text
dirección: jnl3qwwgchhbkammkqajwyuvcnt3shvaio53lnui7zr735hx4ab2slyd.onion
reconstruida desde la dirección: True
período: 3729719 duración (min): 8
clave cegada: 9fac5013...
circuito de un salto -> /tor/hs/3/n6xQEzASD31484ta7ZKChxNX14NTqcIyQlwXma5N9K0: HTTP/1.0 503 Rejecting single hop HS v3 descriptor request
validez 180, revisión 14695413, puntos de introducción 3
   create2-formats 2
   flow-control 1-2 31
   introduction-point AwAGfwAAARPvAhR4dPChvz+XuVSBXw7KiSkEsfo42wMgeF0
   onion-key ntor b0otE3LtQn7qnrGr8SKXxHCTOG9HSomwsQornrxIOCs=
   auth-key
   -----BEGIN ED25519 CERT-----
```

Los valores varían cuando la red se reconstruye. El bloque corresponde a etiquetas localizadas del código español, pero conserva cifras históricas ilustrativas y **no constituye una ejecución nueva**.

Interpretación:

- `onion_address(key_from_address(x)) == x` muestra que no estamos ante un identificador asignado por un registro. La dirección codifica la clave pública, una suma de comprobación y un byte de versión en base32.
- **`duration (min): 8`** refleja el período HSDir acortado de la red privada. La red pública utiliza períodos mucho más largos; aquí se reducen para poder observar cambios durante una sesión.
- **`flow-control 1-2 31`** anuncia control de congestión y `sendme_inc = 31`, el mismo valor observado en el [laboratorio 5](Laboratorio-05-Flujos.md).
- El descriptor contiene tres puntos de introducción en esta configuración.

## Cómo se diagnosticó el fallo original

La primera implementación no consiguió descargar el descriptor de **ninguno** de los ocho HSDir del laboratorio. Después de probarlos todos, elegir mal un HSDir dejó de ser una explicación plausible. Quedaban el cálculo de la clave cegada y la ruta de solicitud.

Se pidió al cliente `tor` de referencia que obtuviera el mismo descriptor mediante ControlPort (`HSFETCH`, después `GETINFO hs/client/desc/id/...`). Su certificado expuso la clave cegada realmente utilizada y coincidió con la calculada por la implementación educativa. Así se aisló el problema: tor rechaza las solicitudes de descriptores onion v3 recibidas por circuitos de un salto. Utilizar uno normal de tres saltos resolvió el error.

La lección general importa más que la anécdota: cuando un experimento falla, busca un valor intermedio que puedas comparar con otra implementación fiable.

## Una limitación que hay que reconocer

La red privada tiene ocho HSDir y el servicio publica en `2 × 4 = 8` de ellos: **todos**. Descargar correctamente un descriptor no demuestra por sí solo que el cálculo de posiciones en el anillo sea correcto.

Los registros del cliente indican qué HSDir se consultó realmente, y ese nodo coincide con una de las posiciones calculadas por el código para el período y la réplica correspondientes. Es evidencia coherente, pero no una demostración completa. Sería necesaria una red con más HSDir o comparar sistemáticamente muchos períodos.

## Vectores y pruebas offline del descriptor

La edición española incorpora dos archivos de referencia de la red privada: `test/data/onion-descriptor.address` y `test/data/onion-descriptor.txt`. Se mantienen **idénticos a los de la edición inglesa**, porque representan material técnico y firmas que no deben alterarse al traducir los comentarios o la documentación.

Los tests conservan los ejemplos de direcciones de la especificación, un caso de checksum incorrecto, la apertura de un descriptor con su clave cegada y el rechazo de un período incorrecto. La verificación no requiere red para procesar estos vectores archivados:

```bash
PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test/test_onion.py
```

La orden no sustituye el experimento de tres saltos con Chutney.

## Verificación automática

El `lab8` del verificador italiano comprueba una red privada en funcionamiento, mientras `test_onion.py` usa vectores firmados guardados para comprobar direcciones, checksum, descriptor, período incorrecto y tiempo de la red pública. Son pruebas diferentes.

La comprobación `lab8` del entorno original reconstruye la dirección, verifica el rechazo de un circuito de un salto y descifra el descriptor con puntos de introducción. El módulo y sus pruebas unitarias están disponibles en español.

## Problemas conocidos

Una carpeta `authorized_clients/` vacía no demuestra por sí misma descubrimiento restringido ni implica necesariamente HTTP `400`. Si la autorización está activada hacen falta archivos correctos y entradas `auth-client`; hay que examinar los logs reales.

| Síntoma | Causa |
|---|---|
| `503 Rejecting single hop HS v3 descriptor request` | Es el control negativo previsto. Utiliza un circuito de tres saltos para descargar el descriptor. |
| `404` de todos los HSDir | Es posible que el servicio no haya publicado todavía o que la clave cegada corresponda a otro período. |
| `400 Invalid HS descriptor` en los registros | Examina el descriptor real, los archivos de autorización y los registros del servicio; una carpeta `authorized_clients` vacía no demuestra por sí sola la causa. Véase [laboratorio 13](Laboratorio-13-Descubrimiento-restringido.md). |

---

# Implementación detallada

`labs/es/codigo/torlab/onion.py` es uno de los módulos más complejos del repositorio. Combina aritmética de curvas elípticas, cálculo de períodos, distribución en anillos y dos capas de cifrado.

## La dirección es la clave

```python
def onion_address(key: bytes) -> str:
    """base32(PUBKEY | CHECKSUM | VERSION) + «.onion» (rend-spec, ONIONADDRESS)."""
    checksum = hashlib.sha3_256(b".onion checksum" + key + bytes([VERSION])).digest()[:2]
    return base64.b32encode(key + checksum + bytes([VERSION])).decode().lower() + ".onion"
```

Una dirección `.onion` v3 contiene 32 bytes de clave pública Ed25519, dos bytes de suma de comprobación y un byte de versión, codificados en base32 minúscula. Los 35 bytes se transforman en 56 caracteres antes del sufijo `.onion`.

No hay ningún registro central que asigne los nombres: la dirección deriva criptográficamente de la clave. La suma de comprobación no proporciona autenticidad frente a un atacante, que podría recalcularla; sirve principalmente para detectar errores de transcripción. El prefijo `".onion checksum"` también separa este dominio de otros usos del hash.

## Factor de cegado

```python
def blinding_factor(A: bytes, period: int, duration_minutes: int) -> int:
    n = b"key-blind" + struct.pack(">QQ", period, duration_minutes)
    h = bytearray(hashlib.sha3_256(b"Derive temporary signing key\x00" + A + BASE_STR + n).digest())
    h[0] &= 248                                    # «clamping», igual que en Ed25519
    h[31] &= 63
    h[31] |= 64
    return int.from_bytes(h, "little")

def blinded_key(A: bytes, period: int, duration_minutes: int) -> bytes:
    """A' = h·A: clave pública del servicio para un período determinado."""
    return _encode_point(_multiply(blinding_factor(A, period, duration_minutes), _decode_point(A)))
```

Este es el mecanismo que cambia la identidad pública mostrada a los HSDir en cada período.

El nonce `N` incorpora el número y la duración del período como dos valores de ocho bytes. Cambiar de período modifica `N` y, por tanto, el escalar y la clave cegada. Los HSDir que almacenan el descriptor de hoy no identifican automáticamente el mismo servicio mañana, a menos que ya conozcan su dirección onion.

La cadena de separación de dominio `"Derive temporary signing key"` acaba en byte cero, según la codificación especificada, lo que distingue este uso de SHA3-256 de operaciones hash no relacionadas.

Las tres operaciones de bits implementan el **clamping** de escalares Ed25519:

| Operación | Efecto | Finalidad |
|---|---|---|
| `h[0] &= 248` | Borra los tres bits inferiores | Hace que el escalar sea múltiplo de ocho |
| `h[31] &= 63` | Borra el bit superior | Mantiene el escalar dentro del intervalo requerido |
| `h[31] |= 64` | Activa el bit 254 | Garantiza la estructura exigida en bits superiores |

**`int.from_bytes(h, "little")`** es otro detalle fácil de confundir. Ed25519 codifica los escalares en little-endian, a diferencia de muchos campos enteros del protocolo Tor. Un error de endianness genera una clave cegada aparentemente válida, pero incorrecta, que suele producir únicamente búsquedas fallidas de descriptores.

`_multiply` implementa multiplicación escalar para este cliente educativo. La aritmética manual de la curva sigue las fórmulas de las fuentes y es adecuada para enseñanza, **no** para criptografía de producción: no está optimizada ni diseñada para resistir canales laterales temporales.

## Períodos de tiempo

`time_period_info()` calcula el número de período y un indicador de SRV actual o anterior, **no obtiene el valor SRV** del consenso. El ejemplo no emplea el SRV para construir el anillo HSDir. El período de prueba proviene del intervalo de votación en este módulo, no de leer el parámetro de consenso `hsdir_interval`; ocho minutos es particular de la configuración privada.

```python
t = time_period_info(valid_after, voting_interval, test_network=True)
Ap = blinded_key(A, t.period, t.duration_minutes)
```

`time_period_info` calcula el período a partir del intervalo de votación e indica si corresponde el SRV actual o el anterior, **sin obtener el SRV en sí**. El anillo de HSDir necesita pasos adicionales.

Los períodos y las fases SRV están desplazados intencionadamente. El cliente debe seleccionar el SRV actual o anterior según la fase del ciclo de rotación. Combinar un período y un SRV incorrectos puede producir un anillo HSDir matemáticamente válido, pero temporalmente equivocado.

La red privada acorta el período a **ocho minutos** para observar el comportamiento en una sesión. `test_network=True` activa las reglas de la red de prueba.

## Descargar y descifrar

**El cálculo del anillo y la descarga son operaciones distintas.** `responsible_hsdirs()` calcula nodos probables dados los identificadores Ed25519, SRV, período y parámetros adecuados. `download_descriptor(blinded, path)` no lo llama: envía `/tor/hs/3/<base64-blinded-key>` mediante `BEGIN_DIR` al último salto facilitado. En este ejemplo `006e` se fija manualmente.

**El descubrimiento restringido no está implementado aquí.** Para descifrar la capa interior no se obtiene la cookie mediante `auth-client` y la clave x25519 de un cliente autorizado. El mecanismo real necesita credenciales; consulta el [laboratorio 13](Laboratorio-13-Descubrimiento-restringido.md).

**Comprobaciones de seguridad en el código:** `parse_descriptor()` verifica que el certificado de tipo 08 esté vinculado a la clave cegada esperada y firmado por ella, comprueba la firma del descriptor y los límites de `descriptor-lifetime` (30–720 minutos). La caducidad del certificado se comprueba con `check_expiration=True`, que debe usar un cliente con datos actuales; el valor predeterminado es `False` porque los descriptores archivados del laboratorio ya han caducado. El decodificador no compara `revision-counter` con descriptores ya almacenados: esa tarea corresponde al cliente. `key_from_address()` rechaza con `ValueError` cualquier dirección que no tenga 56 caracteres Base32 con versión y suma de comprobación correctas.

```python
d = download_descriptor(Ap, [relay("003r"), relay("004r"), relay("006e")])
desc = parse_descriptor(d, A, Ap)
```

La implementación real de `download_descriptor` crea el circuito hasta el último nodo proporcionado y solicita por `BEGIN_DIR` la clave cegada en base64; no calcula el anillo.

**Es necesario un circuito de tres saltos.** Un HSDir rechaza un descriptor v3 solicitado directamente con `503 Rejecting single hop HS v3 descriptor request`: aceptarlo expondría la dirección del solicitante al repetidor de directorio. Es distinto del consenso público del [laboratorio 6](Laboratorio-06-Directorio.md), donde un circuito de un salto sí es apropiado.

`parse_descriptor` hace tres operaciones, en este orden:

1. Verifica que el certificado de clave de firma del descriptor esté emitido para la **clave cegada esperada**, derivada localmente de la dirección onion.
2. Verifica la firma del descriptor.
3. Descifra las capas exterior e interior.

La primera comprobación es esencial: confiar en una identidad cegada únicamente porque la declara el propio descriptor permitiría que el objeto se autenticara a sí mismo.

La capa externa puede descifrarse conociendo la dirección onion; con descubrimiento restringido la capa interna exige recuperar una cookie mediante credenciales x25519 del cliente autorizado. **Este parser educativo no implementa ese proceso**; véase [laboratorio 13](Laboratorio-13-Descubrimiento-restringido.md).

## Por qué importa el método de diagnóstico

Cuando todos los HSDir fallaron, la implementación comparó un valor criptográfico intermedio, la clave cegada, con el que observaba el cliente tor de referencia. Al coincidir, el error pudo aislarse en la solicitud y su transporte, y no en la aritmética de la curva.

La técnica se generaliza: **si un experimento de protocolo falla, identifica un punto de comprobación intermedio y compáralo con una implementación de confianza**. El cliente tor del laboratorio y su ControlPort proporcionan muchos puntos de este tipo.

## Limitación explícita del experimento

Como los ocho HSDir reciben el descriptor, una descarga correcta no verifica completamente el algoritmo de selección del anillo. El registro del cliente aporta una comprobación adicional: el HSDir elegido por tor debe estar entre los previstos para la misma réplica y período. Un experimento más sólido requeriría muchos más HSDir o la comparación de varios períodos.

## Qué debes saber para que funcione

- El servicio debe haber **iniciado y publicado** su descriptor. Tras reiniciar la red puede necesitar cierto tiempo.
- Si todos los HSDir responden `404`, comprueba primero el **cálculo del período**. Comparar períodos adyacentes ayuda a diagnosticar errores de un intervalo.
- Ante `400 Invalid HS descriptor`, comprueba el descriptor, los archivos de autorización y los registros; no atribuyas automáticamente el error a una carpeta `authorized_clients` vacía. Véase [laboratorio 13](Laboratorio-13-Descubrimiento-restringido.md).
- La dirección del servicio está en `labs/es/laboratorio/net/nodes/009h/hidden_service/hostname` y cambia al regenerar la red.

## Procedencia de las fórmulas

| En el código | En la especificación |
|---|---|
| Codificación de dirección onion | rend-spec, *Encoding onion addresses* |
| Factor de cegado y clamping | rend-spec, *Appendix A: Signature scheme with key blinding* |
| Períodos y SRV | rend-spec, *Publishing shared random values* |
| Posiciones del anillo HSDir | rend-spec, *Generating and publishing hidden service descriptors* |
| Capas del descriptor | rend-spec, *Hidden service descriptors: encryption format* |

