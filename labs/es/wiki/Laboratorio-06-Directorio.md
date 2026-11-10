# Laboratorio 6 — Descargar y verificar el consenso

| | |
|---|---|
| **Capítulo** | 12 — El sistema de directorio |
| **¿Requiere la red?** | Sí |
| **Requisitos previos** | Laboratorios 1–5 |
| **Duración** | Unas tres horas de implementación; un minuto para repetir el experimento |
| **Módulo** | `labs/es/codigo/torlab/directory.py` |

## Qué demuestra

El laboratorio presenta el modelo de confianza del directorio y demuestra algunas comprobaciones criptográficas en una red privada. Las autoridades firman el consenso y el resumen SHA-256 de cada microdescriptor aparece en su entrada `m`. **El verificador educativo no establece por sí solo la cadena de confianza completa.**

El laboratorio también verifica que **la comprobación falle cuando corresponde**: cambiar un solo dígito del consenso invalida sus firmas.

## Preparación

El módulo y los datos de prueba están en el repositorio. Estos comandos requieren la red privada en marcha:

```bash
make -C labs/es/laboratorio start
export PYTHONPATH=labs/es/codigo
```

## Ejecutar el experimento

```bash
python3 - <<'EOF'
import base64
from torlab.circuit import build
from torlab.laboratory import relay
from torlab.directory import *

# Circuito de UN salto hasta la autoridad, sin control de congestión:
# es lo que hace tor para estas consultas del directorio.
circ = build([relay("000a")], cc=False)
text = download(circ, "/tor/status-vote/current/consensus-microdesc", 1).decode()
c = parse_consensus(text)
print(f"consenso: {len(text)} bytes; {' '.join(c.header['valid-after'])}"
      f" -> {' '.join(c.header['fresh-until'])}")

cert = parse_certificates(download(circ, "/tor/keys/all", 3).decode())
print(f"método {c.header['consensus-method'][0]}; firmas {len(c.signatures)}; certificados {len(cert)}")
for r in c.relay[:2]:
    print(f"  {r.name} {r.ip}:{r.orport} w={r.bandwidth} indicadores={sorted(r.flag)[:4]}...")

valid, required, _ = verify_consensus(c, cert, 3)
assert valid >= required, "not enough signatures matching the provided test certificates"
print(f"firmas válidas: {valid} (mínimo: {required})")

# Control negativo: cambiar un dígito de un ancho de banda presente.
# Los valores de la red privada cambian entre ejecuciones; no fijar 4096.
import re
bandwidth = re.search(r"Bandwidth=(\d+)", text)
assert bandwidth is not None, "missing Bandwidth field"
altered_text = text.replace(bandwidth.group(0), f"Bandwidth={int(bandwidth.group(1)) + 1}", 1)
assert altered_text != text
modified = parse_consensus(altered_text)
negative_valid = verify_consensus(modified, cert, 3)[0]
assert negative_valid == 0, "modified document passed signature check"
print("consenso modificado, firmas válidas:", negative_valid)

dig = "-".join(base64.b64encode(r.microdesc).decode().rstrip("=") for r in c.relay)
md = parse_microdescriptors(download(circ, f"/tor/micro/d/{dig}", 5).decode())
assert all(r.microdesc in md for r in c.relay), "missing requested microdescriptor"
print(f"microdescriptores: {len(md)}; coinciden con las líneas m: "
      f"{all(r.microdesc in md for r in c.relay)}")
EOF
```

## Resultado del entorno de referencia

`valid-after` y `fresh-until` delimitan el intervalo de *frescura*, mientras que `valid-until` señala por separado la caducidad. Los intervalos cortos de la red privada no son valores universales.

**Límite de seguridad:** este verificador didáctico comprueba las firmas RSA del consenso contra certificados descargados del mismo directorio, pero **no** valida esos certificados frente a claves de identidad preestablecidas y confiables, ni verifica firmas o certificaciones cruzadas, caducidad o vigencia temporal del consenso. Una mayoría de firmas coincidentes **no demuestra** que el documento proceda de autoridades Tor confiables. La cadena de confianza completa queda fuera del ejercicio.

La siguiente salida es histórica e ilustrativa; sus valores no son constantes.

```text
consenso: 5961 bytes; 2026-09-24 16:01:20 -> 2026-09-24 16:01:40
método 36; firmas 3; certificados 3
  test000a 127.0.0.1:5100 w=20 flag=['Authority', 'Fast', 'Guard', 'HSDir']...
  test005r 127.0.0.1:5105 w=4096 flag=['Fast', 'Guard', 'HSDir', 'Running']...
firmas válidas: 3 (mínimo: 2)
consenso modificado, firmas válidas: 0
microdescriptores: 8; coinciden con las líneas m: True
```

El ejemplo histórico conserva la estructura del resultado, pero sus etiquetas están adaptadas a los `print` españoles. Los valores y tiempos dependen de la ejecución.

- El consenso de red privada cubre **40 segundos**, dos intervalos de voto de 20 segundos. La red pública utiliza un período de validez mucho más largo, pero el valor reducido agiliza el laboratorio.
- Hay **tres firmas válidas de tres autoridades** y bastaban dos. La regla de aceptación exige mayoría estricta.
- **`firmas válidas: 0`** después de modificar el consenso es el resultado más importante: un verificador que nunca falla no verifica nada.
- El SHA-256 de los microdescriptores coincide con la entrada `m` correspondiente, lo que muestra la vinculación por digest **sin acreditar todavía los certificados de las autoridades**.

## El detalle que suele causar problemas

La firma no cubre todo el archivo: el texto firmado termina inmediatamente después de la palabra literal `directory-signature `, incluido su espacio final. Los archivos de **CollecTor** también pueden comenzar con una anotación, como `@type network-status-microdesc-consensus-3 1.0`, que **no forma parte del documento firmado**.

Si esa anotación se incluye al calcular el digest, fallan todas las firmas. El síntoma parece criptográfico, pero el error real consiste en delimitar mal el documento. Por ello, `signed_text` debe comenzar en el documento `network-status` verdadero; una prueba de regresión preserva ese comportamiento.

## Comprobación sin conexión con archivos del repositorio

El ejemplo anterior citaba `labs/es/datos/collector`, ruta que **no existe**. La muestra firmada disponible está realmente en `labs/es/codigo/torlab/test/data/`. Para estudiar archivos históricos públicos de CollecTor deben obtenerse por separado el consenso y sus certificados históricos correspondientes. El resultado 3/2 de esta prueba solo indica coincidencia con los certificados aportados, no autenticación confiable.

```python
from pathlib import Path
from torlab.directory import parse_consensus, parse_certificates, verify_consensus
fixture = Path("labs/es/codigo/torlab/test/data")
consensus = parse_consensus((fixture / "consensus-microdesc.txt").read_text())
certificates = parse_certificates((fixture / "authority-certificates.txt").read_text())
matching, required, _ = verify_consensus(consensus, certificates, 3)
assert (matching, required) == (3, 2)  # coincidencia, no anclaje de confianza
```

```bash
PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test/test_directory.py
```

## Verificación automática

El verificador italiano histórico `lab6` prueba la red privada; el `test_directory.py` localizado utiliza documentos guardados. Ninguno establece una raíz de confianza de las autoridades.

## Problemas conocidos

| Síntoma | Causa |
|---|---|
| `RELAY_END NOTDIRECTORY` o HTTP `503` | El primero indica que el repetidor no ofrece directorio; el segundo es un error HTTP del servicio. Examina la respuesta real. |
| `valid signatures: 0` con un consenso público archivado por separado | Revisa `@type`, los certificados históricos correspondientes y los límites del documento firmado; los archivos públicos deben descargarse aparte. |
| HTTP `503` de un directorio | Examina el estado HTTP y escoge una autoridad o caché accesible; un repetidor sin servicio de directorio puede enviar `END NOTDIRECTORY`. |
| El consenso contiene menos repetidores de los esperados | Puede haberse descargado durante una transición de consenso; vuelve a intentarlo después de unos treinta segundos. |

---

# Implementación detallada

El módulo es `labs/es/codigo/torlab/directory.py`. Realiza cuatro tareas: descargar documentos de directorio mediante un circuito, analizarlos, verificar las firmas y vincular los microdescriptores con el consenso.

## Descargar mediante un circuito

```python
def download(circ: Circuit, path: str, stream_id: int) -> bytes:
    """Solicitud HTTP/1.0 GET al servicio de directorio del último salto mediante BEGIN_DIR."""
    s = Stream(circ, stream_id)
    circ.send(RelayMessage(RelayCommand.BEGIN_DIR, stream_id, b""))
    _, msg = s._next()
    if msg.command != RelayCommand.CONNECTED:
        raise CircuitError(f"BEGIN_DIR rechazado: {msg.command}")
    s.send(f"GET {path} HTTP/1.0\r\n\r\n".encode())
    response = s.receive_all()
    header, _, body = response.partition(b"\r\n\r\n")
    state = header.split(b"\r\n")[0]
    if b" 200 " not in state:
        raise CircuitError(f"{path}: {state.decode()}")
    return body
```

`BEGIN_DIR` utiliza el servicio de directorio del último repetidor, sin abrir una conexión TCP externa. El cliente **debe** enviar un cuerpo vacío y el repetidor **debe** ignorar el que reciba. Tras el éxito, el servidor **debe** enviar `CONNECTED` con cuerpo vacío, y el cliente **debe** ignorarlo. Si no existe servicio de directorio, puede devolver `RELAY_END NOTDIRECTORY`, en lugar de HTTP `503`.

Este circuito de un salto es un ejemplo **no anónimo** de acceso a directorios públicos. Tor permite esa modalidad, pero no la exige para todas las peticiones; los descriptores onion tienen requisitos de anonimato diferentes.

```python
circ = build([relay("000a")], cc=False)
```

El circuito **de un salto** sin negociación de control de congestión muestra una modalidad permitida de acceso no anónimo a directorios. No debe interpretarse como el único método de descarga de Tor.

> Este atajo sirve para documentos públicos como el consenso, **no** para descriptores onion. En estos importa el anonimato del solicitante y los HSDir rechazan accesos inapropiados de un salto; véase el [laboratorio 8](Laboratorio-08-Onion.md).

## Formato netdoc

`items` es un analizador didáctico de netdocs previstos, no un validador robusto frente a datos malformados. Un bloque PEM truncado puede provocar una excepción.

```python
def items(text: str) -> list[Item]:
    """Divide un documento en formato netdoc en elementos (dir-spec, netdoc)."""
    output, lines, i = [], text.split("\n"), 0
    while i < len(lines):
        line = lines[i]
        i += 1
        if not line:
            continue
        keyword, *arguments = line.split(" ")
        object_text = None
        if i < len(lines) and lines[i].startswith("-----BEGIN "):
            j = i
            while not lines[j].startswith("-----END "):
                j += 1
            object_text = "\n".join(lines[i:j + 1]).encode()
            i = j + 1
        output.append(Item(keyword, arguments, object_text))
    return output
```

Los documentos de directorio Tor —consensos, votos, descriptores de repetidores, microdescriptores y certificados de autoridades— comparten un metaformato sencillo: palabra clave, argumentos separados por espacios y, opcionalmente, un objeto parecido a PEM en las líneas siguientes. Un pequeño analizador genérico `items` puede servir de base a todos los analizadores específicos.

`parse_consensus` funciona después como una máquina de estados: una línea `r` inicia una entrada de repetidor y las líneas `s`, `w`, `p` y `m` completan sus atributos. `r` incluye sobrenombre, identidad, dirección y puerto; `w` transporta información de ancho de banda; `m` transporta el digest del microdescriptor.

## Límite de la firma: el byte que todos se equivocan al contar

La función real comienza en `network-status-version `, omitiendo `@type` de CollecTor, y termina tras el primer `directory-signature `. La coincidencia RSA **no acredita** la identidad confiable del certificado ni su vigencia.

```python
def signed_text(text: str) -> bytes:
    """Parte del consenso cubierta por las firmas: desde «network-status-version»
    hasta el espacio posterior a «directory-signature» (dir-spec).

    Los archivos de CollecTor pueden empezar por una anotación «@type ...»,
    ajena al documento firmado, que debe excluirse.
    """
    start = text.index("network-status-version ")
    pos = text.index("\ndirectory-signature ") + len("\ndirectory-signature ")
    return text[start:pos].encode()
```

La firma **no cubre todo el documento**: incluye hasta el literal `directory-signature` y el espacio final. Un byte adicional o ausente modifica el digest.

Esto importa especialmente con **CollecTor**, que puede anteponer:

```text
@type network-status-microdesc-consensus-3 1.0
network-status-version 3 microdesc
```

`@type` es metadato del archivo, **no del documento network-status firmado**. Incluirlo hace fallar las firmas simultáneamente, indicio útil de un error de delimitación en vez de una clave incorrecta de una autoridad.

```python
def verify_signature(consensus: Consensus, signature: Signature, cert: AuthorityCertificate) -> bool:
    """La firma es RSA PKCS#1 v1.5 del digest *sin* identificador de algoritmo:
    recuperar el digest de la firma y compararlo con el calculado."""
    h = hashlib.sha256 if signature.algorithm == "sha256" else hashlib.sha1
    expected = h(signed_text(consensus.text)).digest()
    try:
        recovered = cert.signing_key.recover_data_from_signature(
            signature.signature, padding.PKCS1v15(), None)
    except Exception:
        return False
    return recovered == expected
```

`recover_data_from_signature` con algoritmo `None` recupera el digest incorporado por el formato de firma RSA de Tor, sin requerir el `DigestInfo` ASN.1 habitual. Coincide con la construcción histórica explicada por la especificación de directorio. Una llamada genérica de alto nivel a `verify()` que espere un identificador de algoritmo convencional podría rechazar firmas Tor válidas.

El algoritmo hash procede de los metadatos de la firma: los consensos modernos usan SHA-256; el analizador también puede manejar formatos que indican SHA-1 cuando la especificación los permite.

No hace falta comparar en tiempo constante porque tanto el digest esperado como el documento firmado son públicos. En cambio, la comprobación `AUTH` de ntor-v3 del laboratorio 3 usa `hmac.compare_digest` porque implica estado de autenticación derivado de secretos.

## Relación de los resúmenes y límites de confianza

La cadena real parte de **claves de identidad de autoridades previamente confiables**, certificados de firma validados y un consenso vigente correctamente firmado. Solo entonces el SHA-256 de cada entrada `m` vincula un microdescriptor y su `ntor-onion-key` al documento. Este código didáctico solo ilustra la correspondencia de firmas y resúmenes; no constituye un arranque seguro de la red Tor pública.

```text
claves de autoridades confiables → certificados validados → consenso firmado → SHA-256 `m` → microdescriptor → `ntor-onion-key`
```

## Control negativo

Las aserciones demuestran que se han modificado realmente los bytes firmados y que el verificador RSA simplificado detecta esa manipulación. No comprueban la raíz de confianza.

```python
import re
bandwidth = re.search(r"Bandwidth=(\d+)", text)
assert bandwidth is not None, "missing Bandwidth field"
altered_text = text.replace(bandwidth.group(0), f"Bandwidth={int(bandwidth.group(1)) + 1}", 1)
assert altered_text != text
altered = parse_consensus(altered_text)
assert verify_consensus(altered, cert, 3)[0] == 0
```

Un verificador que nunca falla no prueba nada. Modificar un valor y ver que las firmas válidas caen a cero distingue la verificación auténtica de una función que devuelve siempre éxito.

La prueba **no** fija `Bandwidth=4096`. Los valores medidos en la red privada cambian. Si no existiera el valor fijo, `replace` no modificaría nada y el control negativo podría engañarnos. El ejemplo de la red activa y el verificador italiano `lab6` buscan un campo `Bandwidth` presente; las pruebas sobre la muestra fija pueden utilizar el valor conocido `Bandwidth=4096`.

## Qué debes saber para que funcione

- **No todos los repetidores son cachés de directorio.** Los que no ofrecen el servicio pueden devolver `END NOTDIRECTORY`; los servidores HTTP sí pueden responder con `503`. En la red privada usa una autoridad disponible (`000a`, `001a` o `002a`).
- El consenso de laboratorio dura poco intencionadamente. Durante las transiciones pueden verse estados intermedios; repite tras el siguiente voto.
- El consenso de microdescriptores y el consenso completo son **variantes diferentes** de documento, con distintos formatos de línea de repetidor, aunque las firmas sigan principios parecidos.
- La ruta para obtener microdescriptores es `/tor/micro/d/<digests separados por ->`, con digests base64 sin el relleno final `=`.

## Procedencia de las reglas

| En el código | En la especificación |
|---|---|
| `BEGIN_DIR` | tor-spec, *Opening streams and transmitting data* |
| Metaformato netdoc | dir-spec, *netdoc document meta-format* |
| Límite del texto firmado | dir-spec, *Signing documents* |
| Certificados de autoridades | dir-spec, *Directory authority key certificates* |
| Microdescriptores | dir-spec, *Computing microdescriptors* |

