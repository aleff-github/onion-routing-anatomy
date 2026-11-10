# Laboratorio 14 — Comprobar una política de salida

| | |
|---|---|
| **Capítulo** | 22 — Administrar un repetidor |
| **¿Requiere la red?** | Sí, solo la red privada del libro |
| **Requisitos previos** | Laboratorios 1–5 |
| **Duración** | Aproximadamente 1 hora |
| **Script** | `labs/es/laboratorio/politica_salida.py` |

## Qué demuestra

Este experimento muestra qué observa un cliente cuando una salida rechaza un destino: el mensaje `END`, su código de razón y la información que acompaña a esa razón. Tres destinos producen tres resultados diferentes a través de la misma salida.

También permitió descubrir un pequeño defecto de implementación en tor 0.4.9.13.

## Preparación

El entorno español incluye la infraestructura Docker/Chutney. Ejecuta desde la raíz del repositorio y construye primero la imagen con `make -C labs/es/laboratorio image` si es la primera vez. Las ediciones comparten puertos del anfitrión: **no inicies varias redes simultáneamente**. Comandos previstos:

```bash
make -C labs/es/laboratorio start
export PYTHONPATH=labs/es/codigo
```

El script inserta temporalmente `ExitPolicy reject 127.0.0.1:8080` **antes de la primera directiva `ExitPolicy`** porque prevalece la primera coincidencia: prohíbe **una pareja concreta de dirección y puerto**, no el puerto 8080 en todas las direcciones. Antes de modificar el `torrc` exige que 9999 no tenga servidor y que pueda iniciar el servidor HTTP de prueba en 8081. Después realiza las pruebas y trata de restaurar el `torrc`. La orden HUP apunta exclusivamente al PID validado del nodo `006e` (no usa `pkill -f`).

## Ejecutar el experimento

```bash
make -C labs/es/laboratorio politica-salida
```

 Su ejecución requiere la red privada `book` en funcionamiento y las dependencias Python de `torlab` instaladas.

## Ejemplo histórico de resultados (no garantizado)

```text
127.0.0.1:8080 -> END motivo=EXITPOLICY dirección=127.0.0.1 TTL=1800
127.0.0.1:8081 -> CONNECTED
127.0.0.1:9999 -> END motivo=MISC
```

Los **valores de protocolo** se conservan, pero las etiquetas `motivo` y `dirección` reflejan la salida **localizada** del script español. El valor del TTL, la razón del último rechazo y los tiempos pueden variar. Interpretación:

- **8080, `EXITPOLICY`:** la regla temporal rechaza **127.0.0.1:8080**. El mensaje `RELAY_END` puede incluir una dirección IPv4/IPv6 y un **TTL opcional**; la cifra de **1800 segundos no está garantizada** y la especificación admite que los campos adicionales falten o estén incompletos.
- **8081, `CONNECTED`:** la salida permite abrir un flujo TCP hacia el servidor local. Este mensaje no prueba por sí solo que se haya descargado una página HTTP.
- **9999, `MISC` en la captura histórica:** no hay servidor escuchando. `CONNECTREFUSED` es una razón definida por Tor y **también es válida** en otra versión o situación. La prueba actual acepta una de las dos categorías.

## Defecto de tor 0.4.9.13

El análisis de la ejecución de referencia atribuyó `MISC`, en lugar de `CONNECTREFUSED`, a un comportamiento de la implementación y no al analizador del laboratorio.

tor obtiene correctamente `ECONNREFUSED` mediante `getsockopt(SO_ERROR)` y registra el rechazo. Sin embargo, al cerrar el flujo vuelve a calcular la razón de `END` a partir de `tor_socket_errno`, que en Unix se expande a la variable global `errno`. El valor observado sigue siendo `EINPROGRESS` (115), que no se corresponde con una razón concreta de fin de flujo y acaba convertido en `MISC`.

El cliente sabe que el flujo falló, pero puede perder el detalle de que el destino rechazó activamente la conexión. Esta explicación describe una observación **de tor 0.4.9.13**, no una propiedad general. La especificación diferencia `MISC` (1), `CONNECTREFUSED` (3) y `EXITPOLICY` (4).

Por ello, `MISC` aparece en la transcripción histórica. Una versión distinta puede devolver `CONNECTREFUSED` y no debe rechazarse por ese motivo; hay que contrastar los resultados reales con los registros y la versión del nodo.

## ¿Por qué tres saltos en vez de uno?

El script construye un circuito de **tres saltos** para separar la prueba de política de las defensas contra circuitos de un solo salto. En el experimento histórico, un circuito de un salto produjo `END TORPROTOCOL`; la especificación recomienda rechazar esos intentos, pero **no garantiza ese motivo textual**: la implementación también puede destruir el circuito.

## Seguridad y pruebas offline

`politica_salida.py` realiza el experimento únicamente contra `127.0.0.1`, usando los nodos de Chutney `003r`, `005r` y `006e`. Exige que el puerto 9999 esté cerrado y que el servidor 8081 pueda abrirse; una interferencia de otro programa no debe confundirse con una propiedad de Tor. Solo modifica el `torrc` de `006e`, lo restaura en un bloque `finally` y **señala un error si la recarga final falla**, porque restaurar el archivo no demuestra que Tor haya aceptado la configuración. Al terminar también cierra los sockets de circuito y los servidores que creó; una interrupción brusca puede impedir el rollback.

La función `insertar_regla_rechazo` coloca `ExitPolicy reject 127.0.0.1:8080` antes de la primera regla de salida, evitando errores de precedencia. La recarga ahora verifica el PID del proceso `006e` antes de enviar HUP. Las pruebas offline cubren el orden, los mensajes `CONNECTED` y `END`, los datos opcionales y la distinción entre `MISC` y `CONNECTREFUSED`; **no prueban el PID, el reload o el tráfico real**.

```bash
PYTHONPATH=labs/es/codigo:labs/es/laboratorio python3 -m pytest -q labs/es/laboratorio/test_politica_salida.py
```

La prueba offline no sustituye la recarga de `torrc` y la construcción de los circuitos reales.

## Verificación automática

La comprobación **italiana** `scripts/verify_labs.py::lab14` aún compara el texto histórico exacto, incluido `TTL=1800` y `MISC`: puede dar un **falso negativo** con otra versión o TTL. La versión española comprueba las categorías `EXITPOLICY`, `CONNECTED` y `MISC` **o** `CONNECTREFUSED`.

## Problemas conocidos

| Síntoma | Causa |
|---|---|
| Todas las solicitudes devuelven `END TORPROTOCOL` | Verifica si el circuito realmente utiliza tres saltos. Un solo salto es una causa posible, no la única. |
| `8081 -> END motivo=EXITPOLICY` | Revisa el orden de las reglas, la configuración realmente cargada y los servicios de prueba. |
| `No existe una línea ExitPolicy en el torrc de 006e` | Puede que no se use la topología `book` o que `006e` no sea una salida; comprueba el `torrc`. |

Referencias: [Tor Specifications — Closing streams](https://spec.torproject.org/tor-spec/closing-streams.html) y [Opening streams](https://spec.torproject.org/tor-spec/opening-streams.html).
