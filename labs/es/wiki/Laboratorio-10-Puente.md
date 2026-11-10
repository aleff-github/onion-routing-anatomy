# Laboratorio 10 — Un puente obfs4 visto por un censor

| | |
|---|---|
| **Capítulo** | 16 — Censura y transportes conectables |
| **¿Requiere la red?** | Sí, pero con una topología **diferente**: `book-bridge` |
| **Requisitos previos** | Laboratorio 1 (`channel.py`) y red privada `book-bridge` |
| **Duración** | De una a dos horas |
| **Archivos disponibles (sin validación dinámica)** | `labs/es/laboratorio/chutney/networks/book-bridge`, `puente_obfs4.py` y `test_puente_obfs4.py` |

## Qué demuestra

Solo en una **red Chutney privada**, el laboratorio compara registros TLS visibles en un ORPort normal con el tráfico obfs4. En la captura histórica el registro TLS comienza por `16 03 01`, mientras que el flujo obfs4 no se reconoció como TLS. **Es una observación limitada a esa captura, no una prueba de indistinguibilidad absoluta**: los tamaños, los tiempos y una IP de puente conocida pueden seguir siendo observables.

Una sonda TLS genérica no completó la negociación obfs4. Según su especificación, el servidor debe descartar los intercambios inválidos y **se recomienda** retrasar aleatoriamente el cierre; esto no garantiza silencio indefinido.

## Preparación

**Seguridad de los datos:** `make ... clean` elimina el `laboratorio/net/` generado, incluidas claves privadas y registros. Solo debe aplicarse a una red desechable; guarda aparte cualquier evidencia necesaria. Si aún no existe la imagen, ejecuta primero `make -C labs/es/laboratorio image` (`start` no la construye). Las diferentes ediciones comparten puertos del anfitrión: no inicies varias redes a la vez.

Se necesita la topología `book-bridge`, que incorpora una autoridad de puentes (`003ba`), un puente obfs4 (`009br`) y un cliente de ese puente (`011bc`).

La topología Chutney y los comandos Make están en `labs/es/`. Para iniciar el laboratorio 10:

```bash
make -C labs/es/laboratorio clean
make -C labs/es/laboratorio start NETWORK=book-bridge
```

Para volver a la topología ordinaria:

```bash
make -C labs/es/laboratorio clean
make -C labs/es/laboratorio start
```

Con `book-bridge` activo, `make -C labs/es/laboratorio verify` comprobará la comunicación de extremo a extremo de esa topología, **no cambiará automáticamente de red**.

El cliente del puente utiliza el **SocksPort 9011**; el transporte obfs4 escucha en el **puerto 9909**.

## Paso 1 — El cliente se conecta por el puente

```bash
grep -E "new bridge descriptor|Only one bridge|Bootstrapped 100" labs/es/laboratorio/net/nodes/011bc/notice.log
```

Salida histórica de referencia:

```text
[notice] new bridge descriptor 'test009br' (fresh): $DE539956E7E6A323...~test009br at 127.0.0.1
[warn] Only one bridge (transport: 'obfs4') is configured. You should have at least two
       for conflux, for any transport that is not 'snowflake'.
[notice] Bootstrapped 100% (done): Done
```

El registro confirma la obtención de un descriptor del puente configurado y el arranque completo, pero **no demuestra por sí solo por qué conexión se obtuvo**. El cliente necesita de antemano la dirección y los parámetros obfs4 del puente, que no aparece en el consenso público ordinario. El aviso de Conflux se refiere a esta configuración con un único puente; no es un fallo de arranque.

Con un servidor HTTP local escuchando en el puerto 8080:

```bash
docker exec torbook-es-network curl -s -o /dev/null -w "%{http_code}\n" \
  --noproxy "" --socks5-hostname 127.0.0.1:9011 http://127.0.0.1:8080/
```

Resultado esperado: `200`.

## Paso 2 — Qué ve el censor

Antes, en otro terminal, inicia el servidor HTTP solo local: `python3 -m http.server 8080 --bind 127.0.0.1`. Esta captura **sobrescribe** `b1.pcap`, por lo que debes guardar previamente los datos que quieras conservar. Genera ambos tipos de tráfico mientras tcpdump graba y analiza el archivo cuando haya terminado.

Captura dentro del contenedor el tráfico del puerto obfs4 y el de un ORPort ordinario mientras se generan ambas clases de conexiones:

```bash
# Solo red privada y desechable del propio laboratorio
docker exec -u 0 -d torbook-es-network sh -c \
  "timeout 25 tcpdump -i lo -w /lab/net/b1.pcap 'tcp port 9909 or tcp port 5104' >/dev/null 2>&1"
sleep 2
docker exec torbook-es-network curl --silent --show-error --max-time 15 \
  --noproxy "" --socks5-hostname 127.0.0.1:9011 http://127.0.0.1:8080/
# Abre también un canal Tor normal hacia el repetidor local
PYTHONPATH=labs/es/codigo python3 - <<'PY'
from torlab.channel import open_channel
from torlab.laboratory import relay
r = relay("004r", client="010c")
open_channel("127.0.0.1", r.port, expected_identity=r.id_ed)
PY
sleep 27  # esperar al cierre de tcpdump
for p in 5104 9909; do
  echo "== puerto $p =="
  docker exec torbook-es-network tshark -r /lab/net/b1.pcap \
    -Y "tcp.dstport==$p && tcp.len>0" -T fields -e tcp.len -e tcp.payload | head -1
  docker exec torbook-es-network tshark -r /lab/net/b1.pcap \
    -Y "tls && tcp.port==$p" -T fields -e frame.number | wc -l
done
```

**Nota metodológica:** los resultados siguientes proceden de una captura de referencia y varían entre ejecuciones. `16 03 01` es el valor heredado del campo de versión del registro TLS, no la versión finalmente negociada. El filtro `tls` de Wireshark es una clasificación orientativa y no garantiza que obfs4 resulte imposible de identificar por otros medios. Un observador que ya conoce la dirección IP del puente aún puede bloquearla.

Captura del entorno original:

```text
== port 5104, first bytes from the client ==
1533   16030105f8010005f4030305cc9ad005e921614509b15f6151135f983b...
== port 9909, first bytes from the client ==
602    f23abb4e8c3a45ab0e92958157c177bba1cc5dd27e80d74db45d77b425...

== packets recognized as TLS ==
port 5104: 29
port 9909: 0

== obfs4 segment sizes (client -> bridge) ==
602 1762 1308 1414 643 2183 2195 1568 1308 2037 616 1346
```

Interpretación:

- **`16 03 01`** inicia un registro de intercambio TLS. El tráfico del ORPort normal se reconoce como TLS y la dirección puede estar identificada en el consenso público.
- El tráfico del puerto obfs4 no presenta una cabecera TLS comparable. En la captura original **ningún paquete** fue identificado como TLS; los tamaños de los segmentos tampoco correspondían directamente a celdas Tor de 514 bytes.
- Los bytes, cantidades de paquetes y tamaños concretos cambian en cada ejecución. Lo significativo es la diferencia entre TLS reconocible y el transporte ofuscado.

## Paso 3 — Sondear activamente el puente

Un censor que sospeche la existencia de un puente podría conectarse e intentar hablar un protocolo conocido. El módulo de canal del laboratorio 1 está incorporado. El sondeo equivalente puede realizarse mediante el script local, que utiliza únicamente `127.0.0.1:9909`:

```bash
python3 labs/es/laboratorio/puente_obfs4.py sondeo
```

Salida **histórica del cliente TLS original** (el nuevo script español informa de la clase de excepción, no reproduce necesariamente esa cadena):

```text
TimeoutError: _ssl.c:1063: The handshake operation timed out
```

Un `ClientHello` TLS normal es un intercambio obfs4 inválido. En el ensayo original no llegó una respuesta de protocolo útil antes del timeout; un puente también puede cerrar o reiniciar TCP tras un retraso. La línea `_ssl.c` depende de Python/OpenSSL. **Una única sonda sin respuesta no demuestra que el puente sea indetectable** ni impide bloquear una IP conocida. El cliente legítimo necesita los parámetros obfs4 del puente, incluido el certificado.

## Herramientas del laboratorio español

La herramienta `labs/es/laboratorio/puente_obfs4.py` contiene cuatro modos, todos limitados a la red privada del libro. No descarga puentes públicos ni usa objetivos externos.

```bash
# Comprobar en el registro si arrancó el cliente 011bc.
make -C labs/es/laboratorio puente-estado

# Requiere un servidor HTTP local en 127.0.0.1:8080.
make -C labs/es/laboratorio puente-http

# Intentar una negociación TLS contra el puerto obfs4 local.
make -C labs/es/laboratorio puente-sondeo

# Leer una captura existente (no captura automáticamente).
make -C labs/es/laboratorio puente-captura ARCHIVO=b1.pcap
```

Para el segundo comando, primero inicia en otro terminal un servidor de prueba local, por ejemplo:

```bash
python3 -m http.server 8080 --bind 127.0.0.1
```

El analizador de captura compara los primeros bytes de segmentos TCP destinados al ORPort 5104 y al puerto obfs4 9909. Buscar un prefijo compatible con TLS (`16 03`) es una **heurística**, no una prueba criptográfica de ofuscación. Una captura vacía tampoco constituye un resultado positivo.

Se han añadido pruebas unitarias *offline* que no necesitan iniciar Docker, enviar tráfico ni conectarse a la red:

```bash
PYTHONPATH=labs/es/laboratorio python3 -m pytest -q labs/es/laboratorio/test_puente_obfs4.py
```

 La captura y las salidas numéricas anteriores son registros de la edición de referencia.

## Verificación automática

`make -C labs/es/laboratorio verify` ejecuta solo **la verificación de la topología Chutney activa**. No equivale a las seis comprobaciones del `make verifica-lab-bridge` italiano, ni lanza los comandos separados `puente-estado`, `puente-http`, `puente-sondeo` o `puente-captura`.

```bash
make -C labs/es/laboratorio verify
```

Esta orden comprobará la topología **ya activa**. Inicia explícitamente `book-bridge`, verifícala y después limpia el entorno y reinicia `book`.

## Problemas conocidos

`make -C labs/es/laboratorio clean` debe reservarse a la red desechable. `pkill -x tor` terminaría **todos** los procesos Tor del contenedor seleccionado, no solo un puente.

| Síntoma | Causa |
|---|---|
| El arranque de la red de puentes nunca termina | Procesos `tor` de la topología anterior podrían conservar los puertos. Solo en el contenedor desechable, detén esos procesos con `docker exec torbook-es-network pkill -x tor`. |
| `011bc` no arranca | Los clientes pertenecen a la fase 2: `CHUTNEY_LAUNCH_PHASE=2 chutney start`. |
| `tshark` no encuentra paquetes | La captura empezó después de enviar el tráfico. Inicia `tcpdump`, espera un momento y genera las conexiones. |
| Los números de nodo no coinciden | Chutney numera según el orden de la topología `labs/es/laboratorio/chutney/networks/book-bridge`; comprueba `labs/es/laboratorio/net/nodes/`. |

