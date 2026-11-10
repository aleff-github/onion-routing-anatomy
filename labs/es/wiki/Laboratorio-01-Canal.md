# Laboratorio 1 — Abrir un canal verificado

| | |
|---|---|
| **Capítulo** | 7 — Canales: TLS y el intercambio inicial |
| **¿Requiere la red?** | Sí |
| **Requisitos previos** | Laboratorio 2 (`cells.py`); `cryptography` |
| **Duración** | De dos a tres horas de implementación; aproximadamente un minuto para repetirlo |
| **Módulo disponible** | `labs/es/codigo/torlab/channel.py` |

**Orden de aprendizaje:** aunque este es el laboratorio 1, necesita el codificador de celdas del laboratorio 2 (`cells.py`). El módulo ya está incluido en el repositorio; si se implementa todo desde cero, primero hay que estudiar o desarrollar ese componente.

## Qué demuestra

El certificado TLS de un repetidor **no demuestra su identidad**. Es autofirmado y cualquiera puede generar uno. El repetidor demuestra su identidad *dentro* del canal mediante la celda `CERTS`. Así vincula su identidad Ed25519 a una clave de firma y esa clave a la huella del certificado TLS utilizado. Verificar toda la cadena y comparar después la identidad obtenida con la del repetidor al que pretendíamos conectarnos impide que un intermediario suplante al repetidor seleccionado.

## Preparación

Comandos previstos cuando exista el entorno ejecutable español:

```bash
make -C labs/es/laboratorio start      # si la red todavía no está funcionando
export PYTHONPATH=labs/es/codigo
```

## Ejecutar el experimento

```bash
python3 - <<'EOF'
from torlab.channel import open_channel, identity_from_file

expected = identity_from_file("labs/es/laboratorio/net/nodes/003r/fingerprint-ed25519")
c = open_channel("127.0.0.1", 5103, expected_identity=expected)
print(c.version, c.ed_identity.hex()[:16] + "...", c.netinfo, c.auth_methods)
for r in c.registry:
    print("  ", r)

# Control negativo: tipo de repetidor correcto, pero otra identidad.
try:
    open_channel("127.0.0.1", 5104, expected_identity=expected)
except Exception as e:
    print("puerto 5104 con identidad de 003r ->", e)
EOF
```

## Resultado del entorno de referencia

```text
5 785d3199f21d20ad... Netinfo(timestamp=1790265613, peer_address='127.0.0.1', my_addresses=['127.0.0.1']) [3]
   TLS TLSv1.3 TLS_AES_256_GCM_SHA384
   <- VERSIONS (6 byte)
   <- CERTS (1456 byte)
   <- AUTH_CHALLENGE (36 byte)
   <- NETINFO (509 byte)
   -> NETINFO: channel open

port 5104 with 003r identity -> the relay has a different identity from the expected one
```

Esta es la salida inglesa original, no una ejecución de la edición española. Su interpretación:

- **`5`** es la versión negociada del protocolo de enlace. Ofrecemos las versiones 4 y 5, como Arti; la versión 3 ya no resulta útil en este caso.
- La identidad hexadecimal **será diferente** de la del ejemplo: inicializar otra vez la red genera nuevas claves. La longitud de `CERTS` también depende de los certificados y puede variar.
- **`[3]`** indica los métodos de autenticación que el repetidor aceptaría de *otro repetidor*. Nosotros actuamos como cliente y no nos autenticamos. Si un cliente lo hiciera, podría adquirir una identidad estable y reconocible entre canales, lo contrario de nuestro objetivo.
- En `NETINFO`, el repetidor envía su hora y la dirección desde la que nos ve llegar. Nuestra respuesta proporciona deliberadamente **marca temporal cero y ninguna dirección**: un cliente no debe revelar su reloj ni sus direcciones.
- **En la referencia histórica**, el canal recién abierto no presenta celdas `PADDING`. Su aparición depende del uso de circuitos, la negociación y los parámetros de red; abrir un enlace de un salto no obliga a enviar relleno. El ejemplo de varios saltos del [laboratorio 4](Laboratorio-04-Cifrado.md) permite estudiar este comportamiento, pero una ejecución concreta puede diferir.

## El control negativo esencial

La última línea es la parte más importante. Nos conectamos a `004r` afirmando que esperamos `003r`, y el código rechaza correctamente la conexión. Una implementación que verifique firmas y fechas de caducidad, pero **no compare la identidad obtenida con la esperada**, podría superar todas las pruebas positivas sin proporcionar protección frente a una sustitución de repetidor.

## Verificación automática

El verificador italiano contiene una función `lab1` que examina `003r`, `006e` y `000a` y rechaza una identidad equivocada; **no existe un comando `lab1` independiente en el entorno español**. Con la red privada activa, ejecuta manualmente el ejemplo y después las pruebas `PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test/test_channel.py`. `make -C labs/es/laboratorio verify` comprueba la topología Chutney activa; no sustituye el experimento ni constituye una validación de los veinte laboratorios.

Las pruebas independientes de la red de `test_channel.py` construyen una cadena válida utilizando dos claves nuevas, y después la corrompen de diversas maneras exigidas por la especificación: firma inválida, clave de firma no certificada, huella TLS diferente, certificado caducado y tipo de certificado duplicado. Deben rechazarse todas las variantes inválidas.

## Problemas conocidos

| Síntoma | Causa |
|---|---|
| `ConnectionRefusedError` en el puerto 5103 | La red no está iniciada; consulta `make -C labs/es/laboratorio status` cuando esté disponible. |
| `the relay has a different identity from the expected one` en el puerto correcto | Reiniciaste la red con claves nuevas y conservaste una huella anterior. Vuelve a leer `fingerprint-ed25519`. |
| `unexpected cell during the handshake` | Estás hablando con algo que no es un repetidor Tor, posiblemente por usar el puerto equivocado. |

## Continuación

El canal es la base de todo lo demás. El [laboratorio 3](Laboratorio-03-Handshake.md) construirá circuitos encima de él.

---

# Implementación detallada

`labs/es/codigo/torlab/channel.py` ya contiene unas 260 líneas. Abre una conexión TLS, verifica la identidad del otro extremo y devuelve un objeto `Channel` que permite a los laboratorios posteriores enviar celdas.

Los fragmentos siguientes proceden de `labs/es/codigo/torlab/channel.py`. Dependen de importaciones y constantes del módulo completo y no deben ejecutarse como programas independientes.

## Por qué TLS no basta

```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
```

A una persona con experiencia en seguridad, estas tres líneas pueden parecerle un error grave. En este contexto concreto no lo son.

El certificado TLS del repetidor Tor es **autofirmado** y no contiene un nombre de dominio verificable. Ninguna autoridad certificadora autentica los repetidores; validar mediante las CA habituales no tendría sentido. Activar la validación estándar de Python haría fallar todas las conexiones. La identidad se verifica **dentro** del canal mediante `CERTS`, cuya cadena se vincula a la sesión TLS real mediante la huella del certificado.

En otras palabras: TLS cifra el canal; Tor autentica al repetidor.

> Copiar estas tres líneas a un cliente HTTPS corriente **desactivaría sus protecciones basadas en certificados**. Solo son adecuadas en este ejemplo delimitado de canal Tor porque el código comprueba inmediatamente toda la cadena de certificados Tor y la compara con una identidad elegida previamente.

```python
if os.environ.get("SSLKEYLOGFILE"):
    ctx.keylog_filename = os.environ["SSLKEYLOGFILE"]
```

Se sigue la convención de los navegadores: si `SSLKEYLOGFILE` está definida, la biblioteca TLS exporta secretos de sesión para que Wireshark pueda descifrar una captura. Esto permite el [laboratorio 12](Laboratorio-12-Trafico.md). Desciframos **nuestro propio** tráfico mediante claves exportadas voluntariamente por nuestro programa.

```python
source = (source_address, 0) if source_address else None
```

El parámetro `source_address` elige la dirección IP local de origen, por ejemplo `127.0.0.2`. El [laboratorio 9](Laboratorio-09-DoS.md) lo utiliza para variar la IP y estudiar los contadores anti-DoS en pruebas controladas.

## Cadena de certificados

```python
def verify_responder_identity(certificates: dict[int, bytes], cert_tls_der: bytes) -> bytes:
    """Aplica las reglas para autenticar al repetidor mediante CERTS.

    Devuelve KP_relayid_ed (32 bytes) si es válida la cadena
        identidad Ed25519 -> clave de firma -> certificado TLS;
    de lo contrario, lanza ChannelError.
    """
    try:
        id_v_sign = decode_ed_certificate(certificates[CERT_IDENTITY_V_SIGNING])
        sign_v_tls = decode_ed_certificate(certificates[CERT_SIGNING_V_TLS_CERT])
    except KeyError as e:
        raise ChannelError(f"falta el certificado de tipo {e.args[0]}") from None

    identity = id_v_sign.signing_key
    if identity is None:
        raise ChannelError("IDENTITY_V_SIGNING sin clave de firma")
    id_v_sign.verify_signature(identity)                      # firmado con la propia clave de identidad
    signing_key = id_v_sign.certified_key             # KP_relaysign_ed
    sign_v_tls.verify_signature(signing_key)
    if sign_v_tls.certified_key != hashlib.sha256(cert_tls_der).digest():
        raise ChannelError("SIGNING_V_TLS_CERT no coincide con el certificado TLS recibido")
    for c in (id_v_sign, sign_v_tls):
        if c.expired():
            raise ChannelError(f"certificado de tipo {c.kind} caducado")
    return identity
```

Esta función realiza varias comprobaciones de autenticación:

| Componente | Qué hace | Qué impide |
|---|---|---|
| Tipo 4 | Vincula la identidad del repetidor a su clave de firma | Que claves arbitrarias suplanten al repetidor |
| `signing_key` | Lee **quién firmó** desde la extensión 4 | Inferir una identidad en vez de extraerla del certificado |
| Autofirma | Comprueba la coherencia interna del certificado tipo 4 | Por sí sola, poco: cualquiera puede autofirmar un certificado |
| Tipo 5 | Vincula la clave de firma al certificado TLS | Usar una cadena ajena a la sesión actual |
| Huella SHA-256 | Vincula todo a **esta conexión** | Que un intermediario presente certificados auténticos de otro repetidor en su propia sesión TLS |
| Caducidad | Rechaza certificados obsoletos | Aceptar claves de firma retiradas |

La comprobación más importante es comparar la huella del certificado TLS. De lo contrario, la cadena podría ser auténtica pero inútil: probaría que *existe* un repetidor con cierta identidad, no que estamos hablando con él.

**La identidad no es un campo habitual del certificado:** es la clave que lo firmó, transportada en la extensión 4. El certificado dice, en esencia: «Yo, X, certifico la clave Y». X debe leerse de esa extensión y no inferirse del origen del certificado.

## La comprobación que falta en esa función

```python
identity = verify_responder_identity(certificates, cert_tls)
if expected_identity is not None and identity != expected_identity:
    raise ChannelError("la identidad del repetidor es distinta de la esperada")
```

Una cadena válida demuestra que hablamos con **un** repetidor, no necesariamente **el que elegimos**. Compararla con la identidad esperada convierte la validación en autenticación del interlocutor previsto. Esa es la comprobación que hacemos fallar deliberadamente al conectarnos al puerto 5104 con la huella de `003r`.

En este laboratorio es imprescindible pasar `expected_identity`: la función permite `None`, pero entonces omite la comparación con la identidad del repetidor seleccionado.

Sin esta comparación, una implementación podría superar pruebas positivas de firma y caducidad sin proteger contra la sustitución.

## Bucle del intercambio inicial

```python
while netinfo is None:
    cell, buffer = _read(sock, buffer, version)
    registry.append(f"<- {CellCommand(cell.command).name} ({len(cell.body)} bytes)")
    if cell.command == CellCommand.VERSIONS:
        if version:
            continue                                  # ignorar las celdas VERSIONS posteriores
        version = negotiate_version(SUPPORTED_VERSIONS, cell.body)
    elif cell.command == CellCommand.VPADDING:
        continue
    elif cell.command == CellCommand.CERTS:
        certificates = decode_certs(cell.body)
    elif cell.command == CellCommand.AUTH_CHALLENGE:
        (n,) = struct.unpack(">H", cell.body[32:34])
        methods = [m for (m,) in struct.iter_unpack(">H", cell.body[34:34 + 2 * n])]
    elif cell.command == CellCommand.NETINFO:
        netinfo = decode_netinfo(cell.body)
    else:
        raise ChannelError(f"celda inesperada durante el intercambio inicial: {cell.command}")
```

- **El bucle termina cuando llega `NETINFO`**, no después de un número fijo de celdas. El intercambio acaba con el mensaje exigido por el protocolo; las celdas intermedias pueden variar.
- Una segunda celda `VERSIONS` se **ignora**, como exige la especificación. Sin `continue`, otra celda podría renegociar inesperadamente la versión a mitad del intercambio.
- `AUTH_CHALLENGE` solo se interpreta para registrar los métodos ofrecidos. Actuamos como cliente y no nos autenticamos: hacerlo podría proporcionar al repetidor una identidad reconocible entre canales.
- La última rama es crucial: **todo lo que no esté permitido expresamente es un error**. `VPADDING` puede descartarse porque la especificación la permite en cualquier momento. Cualquier otra celda inesperada se rechaza. Sustituir la rama por `else: pass` parecería más tolerante, pero admitiría secuencias arbitrarias.

Justo después del bucle hay una comprobación fácil de olvidar:

```python
if certificates is None:
    raise ChannelError("NETINFO recibido antes de CERTS")
```

Sin ella, un interlocutor hostil podría enviar `NETINFO` inmediatamente y saltarse la autenticación. El bucle acabaría pasando `None` a `verify_responder_identity`.

## Nuestro NETINFO

```python
channel.send(client_netinfo_cell(host))
```

La respuesta `NETINFO` lleva **marca temporal cero y ninguna dirección propia**. No es un atajo didáctico: un cliente Tor real actúa igual. Declarar la hora del reloj podría revelar una desviación relativamente estable; declarar direcciones expondría información que el cliente no debería entregar.

## Qué debes saber para que funcione

- **Las huellas cambian cada vez que reinicializas la red.** `identity_from_file` lee `labs/es/laboratorio/net/nodes/<nodo>/fingerprint-ed25519`. El contenido tiene la forma `<nombre> <clave-base64>`, sin relleno `=` final; el código lo reconstruye antes de descodificar.
- **El puerto es siempre `5100 + número de nodo`.**
- Este canal **no envía relleno** ni mantiene activamente viva la conexión. Un canal inactivo puede ser cerrado tras unos minutos (capítulo 7).
- Un canal recién abierto no recibe `PADDING`. El repetidor lo activa cuando el canal ha transportado un circuito **completo** que se extiende más allá del propio repetidor o tráfico de usuario. En `channelpadding.c` estas situaciones corresponden a `CHANNEL_USED_FOR_FULL_CIRCS` y `CHANNEL_USED_FOR_USER_TRAFFIC`. Los circuitos de un salto del laboratorio no cumplen esas condiciones; el relleno aparece en el [laboratorio 4](Laboratorio-04-Cifrado.md). Una vez alcanzado el umbral, el relleno puede comenzar **antes** de los primeros datos de aplicación, conforme al parámetro de consenso `nf_pad_before_usage`, cuyo valor predeterminado es 1.

## Procedencia de las reglas

| En el código | En la especificación |
|---|---|
| Secuencia del intercambio | tor-spec, *Negotiating and initializing channels* |
| Verificación de certificados | tor-spec, *Authenticating the responder from its CERTS* |
| Formato de certificado Ed25519 | cert-spec, *Tor Ed25519 Certificates* |
| Tipos 4 y 5, extensión 4 | cert-spec, *Certificate types (CERT_TYPE field)* |
| Contenido de NETINFO | tor-spec, *NETINFO cells* |
| Formato de AUTH_CHALLENGE | tor-spec, *AUTH_CHALLENGE cells* |

