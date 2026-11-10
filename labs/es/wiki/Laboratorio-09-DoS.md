# Laboratorio 9 — Activar las defensas contra DoS

| | |
|---|---|
| **Capítulo** | 15 — Defensas contra DoS y gestión de recursos |
| **¿Requiere la red?** | Sí, con imagen compilada mediante `--enable-gpl` |
| **Requisitos previos** | Laboratorios 1–8 |
| **Duración** | Aproximadamente dos horas |
| **Módulo** | `labs/es/codigo/torlab/pow.py` |

> **Ejecuta estas pruebas solo en tu red privada.** El laboratorio genera tráfico anómalo deliberadamente. Repetirlo contra repetidores o servicios reales afectaría a otros usuarios y podría ser ilegal; consulta el capítulo 25.

## Qué demuestra

**Alcance:** nueve circuitos aceptados de treinta es un resultado histórico de una versión de Tor y una secuencia de pruebas, **no una garantía universal**. El depósito de tokens se recupera con el tiempo y la defensa depende del estado previo de la dirección IP. Nunca se debe ejecutar fuera de la red Chutney privada y desechable propia.

Las defensas anti-DoS de un repetidor pueden observarse desde fuera y su comportamiento es más sutil de lo que sugiere una lectura rápida de la documentación. En el experimento de referencia, un límite de ráfaga de 10 permitió **9** creaciones de circuitos antes de rechazar la décima; las conexiones desde `127.0.0.1` **no estaban exentas**.

También examinamos la prueba de trabajo de los servicios onion: cómo se activa, qué aparece en el descriptor y por qué el esfuerzo esperado crece aproximadamente de forma lineal.

## Preparación

Si la imagen todavía no existe, ejecuta primero `make -C labs/es/laboratorio image`; `start` requiere una imagen preparada. Comprueba por separado el módulo PoW y la compilación GPL:

El módulo de simulación Blake2b tiene sus pruebas unitarias. Para el experimento DoS de red, la imagen y Chutney todavía deben construirse y verificarse:

```bash
make -C labs/es/laboratorio start
export PYTHONPATH=labs/es/codigo
```

La imagen debe incorporar el módulo de prueba de trabajo compilado con la opción GPL. La imagen del entorno español tiene definida una etiqueta propia y permitirá verificar el módulo, por ejemplo, después de construirla:

```bash
docker run --rm torbook-es-lab:latest tor --list-modules
docker run --rm torbook-es-lab:latest tor --version
```

La salida `pow: yes` de `tor --list-modules` confirma el módulo PoW. `tor --version` debe mostrar por separado que la compilación es GPL, necesaria para la biblioteca Equi-X.

Comprueba que el módulo `pow` aparezca como disponible. La etiqueta `torbook-es-lab:latest` figura en el Makefile español, pero **no se ha comprobado que la imagen esté construida ni que el módulo esté disponible**.

## Parte 1 — Límites de creación de circuitos

**Antes de modificar la configuración**, verifica que solo se ejecuta la red privada correcta. Se envía HUP al PID exacto del nodo dentro de su contenedor, evitando coincidencias ambiguas con nombres de procesos. `finally` restaura el archivo, pero si falla la señal o el reinicio debe comprobarse manualmente el estado y los registros.

El experimento añade temporalmente límites muy bajos al `torrc` de `003r`, recarga el repetidor, envía 30 solicitudes `CREATE_FAST` consecutivas y restaura el archivo original mediante `finally`, incluso si aparece un error.

```bash
python3 - <<'EOF'
import subprocess, time
from collections import Counter
from torlab.channel import open_channel
from torlab.cells import Cell, CellCommand
from torlab.laboratory import relay, NODES
from torlab.ntor import create_fast_client

torrc = NODES / "003r" / "torrc"
original = torrc.read_text()
hup = ["docker", "exec", "torbook-es-network", "sh", "-c",
       "kill -HUP $(cat /lab/net/nodes/003r/pid)"]
try:
    torrc.write_text(original + """
DoSCircuitCreationEnabled 1
DoSCircuitCreationMinConnections 2
DoSCircuitCreationRate 1
DoSCircuitCreationBurst 10
DoSCircuitCreationDefenseType 2
DoSCircuitCreationDefenseTimePeriod 60 seconds
""")
    subprocess.run(hup, check=True); time.sleep(2)
    g = relay("003r")
    for source, channel_count in (("127.0.0.2", 2), ("127.0.0.3", 1), ("127.0.0.1", 2)):
        channels = [open_channel("127.0.0.1", g.port, expected_identity=g.id_ed,
                                 source_address=source) for _ in range(channel_count)]
        results, reasons, first_rejection = [], Counter(), None
        for i in range(30):
            x, body = create_fast_client()
            channels[0].send(Cell(0x80000100 + i, CellCommand.CREATE_FAST, body))
            r = channels[0].receive()
            while r.command in (CellCommand.PADDING, CellCommand.VPADDING):
                r = channels[0].receive()
            ok = r.command == CellCommand.CREATED_FAST
            results.append(ok)
            if not ok:
                reasons[r.body[0]] += 1
                first_rejection = first_rejection or i + 1
        m = ", ".join(f"DESTROY({k})" for k in reasons)
        print(f"origen {source}, {channel_count} {'canal' if channel_count == 1 else 'canales'}: {results.count(True)} correctos, "
              f"{30-results.count(True)} {m or '-'}; primer rechazo: {first_rejection}")
finally:
    torrc.write_text(original)
    subprocess.run(hup)
EOF
```

Resultados de referencia de las tres ejecuciones:

```text
origen 127.0.0.2, 2 canales: 9 correctos, 21 DESTROY(5); primer rechazo: 10
origen 127.0.0.3, 1 canal: 30 correctos, 0 -; primer rechazo: None
origen 127.0.0.1, 2 canales: 9 correctos, 21 DESTROY(5); primer rechazo: 10
```

Los ejemplos de salida están localizados conforme a los `print` españoles, pero los números son históricos e ilustrativos: una ejecución real puede producir otros recuentos.

**Resultados históricos ilustrativos, no valores obligatorios:** el ritmo de peticiones, la recuperación de tokens y el estado previo pueden alterar el resultado. Registra los eventos reales y no presupongas nueve creaciones aceptadas en cualquier ejecución.

Tres detalles importantes:

1. El rechazo llega como **`DESTROY` de razón 5**, `RESOURCELIMIT`.
2. Con una ráfaga configurada de 10, el programa original aceptó **9** circuitos. La implementación marca al cliente en cuanto el depósito de tokens llega a cero, por lo que la décima solicitud ya se rechaza.
3. Con **un solo canal** no se activa esta defensa en la configuración de prueba, porque `MinConnections` exige al menos dos conexiones simultáneas.

El experimento también refutó la hipótesis de que las conexiones de bucle local estuvieran exentas. La implementación estudiada en `dos.c` no contempla dicha excepción para esta defensa.

Se utilizan direcciones de origen distintas para comenzar cada prueba con una identidad de contabilización nueva. Una dirección marcada continúa sometida a la defensa durante el intervalo configurado.

## Parte 2 — Prueba de trabajo del servicio onion

Esta opción modifica la configuración del servicio onion, no una prueba temporal de Python. Guarda una copia del `torrc` original de `009h`, recarga por PID tras editarlo y **restaura el archivo seguido de otra recarga** al terminar. Si la restauración falla, reconstruye la red desechable en lugar de conservar un estado desconocido.

La línea `pow-params` es histórica: semilla, expiración UTC y esfuerzo sugerido pueden variar. Un esfuerzo cero significa que en ese momento no se exigía trabajo, pero no demuestra por sí mismo una cola vacía. La caducidad de la semilla usa un intervalo recomendado de 105–120 minutos.

Se añade esta opción al `torrc` de `009h`, después de las líneas `HiddenService`:

```text
HiddenServicePoWDefensesEnabled 1
```

Después se recarga la configuración del servicio de prueba; en el contenedor español previsto:

```bash
docker exec torbook-es-network sh -c 'kill -HUP $(cat /lab/net/nodes/009h/pid)'
```

Cuando se publique el nuevo descriptor, se podrá descargar mediante el [laboratorio 8](Laboratorio-08-Onion.md). En la segunda capa aparecerá una línea `pow-params` semejante a la del registro original:

```text
pow-params v1 9qe8kJUi30tgcAlInd5a+trFeVl1yjQtPRb0F4u9C7Y= 0 2026-09-24T17:56:10
```

Contiene el esquema `v1`, una semilla en base64, el esfuerzo sugerido y el momento de caducidad de la semilla. El esfuerzo observado era cero porque la cola del servicio aún no estaba congestionada.

Después de enviar `HUP`, permite que transcurra tiempo suficiente para que el descriptor se publique y se propague por la red privada.

## Parte 3 — El trabajo crece linealmente

**Esto solo simula el umbral Blake2b mediante Monte Carlo; no resuelve Equi-X.** Los 16 bytes aleatorios de `solution` no constituyen una prueba Equi-X válida. El protocolo real v1 exige Equi-X más la comprobación Blake2b; aquí únicamente se observa la probabilidad de superar el segundo control, aproximadamente `1/effort` para esfuerzo positivo.

La biblioteca estándar de Python no implementa Equi-X, pero el laboratorio educativo aísla la comprobación basada en Blake2b para ilustrar su relación probabilística mediante soluciones candidatas aleatorias:

```bash
python3 - <<'EOF'
import os, statistics
from torlab.pow import required_attempts

id_service, seed = os.urandom(32), os.urandom(32)
for effort in (1, 10, 100, 1000):
    trials = [required_attempts(effort, id_service, seed) for _ in range(400)]
    print(f"esfuerzo {effort:>4}: {statistics.mean(trials):.1f} intentos")
EOF
```

Resultado de referencia:

```text
esfuerzo    1: 1.0 intentos
esfuerzo   10: 10.5 intentos
esfuerzo  100: 90.0 intentos
esfuerzo 1000: 1027.7 intentos
```

Los valores concretos cambian en cada ejecución porque las muestras son aleatorias. El número esperado de intentos crece aproximadamente en proporción al esfuerzo elegido.

Un error importante: Blake2b con `digest_size=4` **no equivale** a calcular el Blake2b habitual de 64 bytes y truncarlo a cuatro, ya que la longitud de salida forma parte de los parámetros internos y modifica el cálculo del hash.

## Prueba unitaria de Blake2b

El módulo español `torlab.pow` implementa solamente la comprobación del umbral Blake2b de la prueba de trabajo. **No implementa Equi-X** ni reproduce una solución válida completa del protocolo PoW. Sus soluciones simuladas permiten estudiar la probabilidad de aceptación, sin suponer que sustituyen la prueba de trabajo real de un servicio onion.

La prueba `test_pow.py` compara los límites de aceptación y realiza muestras estadísticas para esfuerzos 10 y 40; este segundo control es probabilístico y debe interpretarse como tal. Se ejecutará mediante:

```bash
PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test/test_pow.py
```

 El código de simulación es independiente del experimento de red que cambia temporalmente `torrc`: la prueba unitaria no demuestra que la defensa anti-DoS del repetidor funcione.

## Verificación automática

El verificador italiano `lab9` utiliza dos canales y una IP de origen nueva en la red privada y comprueba el resultado de referencia de nueve aceptados. La página compara además una y dos conexiones. El `test_pow.py` sin conexión, documentado en la sección anterior, solo evalúa el umbral Blake2b y estadísticas (300 simulaciones con esfuerzos 10 y 40), sin probar el DoS de red ni Equi-X.

La comprobación histórica italiana `lab9` prueba exclusivamente la parte 1 en una red en ejecución y exige el resultado de referencia de nueve circuitos aceptados. La unidad offline `test_pow.py` es diferente y verifica el umbral Blake2b y medias estadísticas; no constituye una comprobación de la defensa en red.

## Problemas conocidos

| Síntoma | Causa |
|---|---|
| Se rechazan de inmediato los 30 circuitos | La dirección de origen sigue marcada por una prueba anterior. Espera el intervalo configurado o utiliza otra dirección de prueba del bucle local. |
| No hay rechazo con dos canales | El repetidor podría no haber recargado la configuración. Consulta `notice.log` de `003r`. |
| No aparece `pow-params` | La imagen podría carecer de `--enable-gpl` o el descriptor nuevo aún no se ha publicado. |

