# Laboratorio 17 — El límite de las celdas RELAY_EARLY

| | |
|---|---|
| **Capítulo** | 27 — Casos reales de ataques contra la red |
| **¿Requiere la red?** | Sí, únicamente la red privada Chutney |
| **Requisitos previos** | Laboratorios 1–4; Docker y red privada disponible |
| **Duración** | Aproximadamente una hora |
| **Script** | `labs/es/laboratorio/relay_early.py` |

## Objetivo y límites

La especificación de Tor define un cupo de **ocho celdas `RELAY_EARLY` por circuito en dirección del cliente hacia la red**. Cuando se supera ese número, el nodo **SHOULD** (debería) cerrar el circuito; la norma **no dice MUST**, por lo que **no garantiza** un determinado `DESTROY`, ni específicamente el motivo 1, en toda implementación. En la dirección **hacia el cliente**, cualquier `RELAY_EARLY` inesperado debe provocar el cierre inmediato: aquí la especificación sí utiliza **MUST**.

En **2014**, repetidores maliciosos que actuaban como HSDir enviaban etiquetas ocultas **hacia el cliente** alternando los tipos externos `RELAY` y `RELAY_EARLY`. Guardias cómplices podían reconocerlas y relacionar la dirección IP del cliente con una **solicitud del descriptor de un servicio onion**, **no necesariamente con la visita de una página**. El límite saliente existía desde 2008; el cambio de 2014 reforzó la defensa en dirección entrante.

**Limitación principal:** el código crea un **circuito de un solo salto al repetidor privado `004r`** y envía deliberadamente mensajes **`DROP` dentro de celdas `RELAY_EARLY`**. Este uso **no cumple la norma aplicable a los clientes**, que solo deben insertar `EXTEND`/`EXTEND2` en esas celdas. Es una **prueba educativa expresamente no conforme**, no un ensayo completo de conformidad con el protocolo.

## Preparación

Desde la raíz del repositorio, construye primero la imagen si fuera necesario e inicia solo la red privada española. Las otras ediciones pueden compartir puertos del anfitrión.

```bash
# Primera ejecución: make -C labs/es/laboratorio image
make -C labs/es/laboratorio start
```

## Ejecución

```bash
make -C labs/es/laboratorio relay-early CANTIDADES='8 9'
```

Este objetivo de Makefile ejecuta **`relay_early.py` en el equipo anfitrión**, usando `PYTHONPATH=../codigo` desde `labs/es/laboratorio`; la topología Chutney usa `--network host`. No es una ejecución Python dentro del contenedor. Los números **8 y 9** corresponden a **pruebas independientes en circuitos nuevos**. Se prohíben cantidades distintas y duplicadas.

Tras el envío experimental de `DROP`, se prueba `BEGIN_DIR` para observar si el circuito sigue activo. El script cierra siempre el canal en `finally`, devuelve un error ante resultados distintos de la referencia y normaliza el mensaje inglés `circuit destroyed, reason 1` producido por la biblioteca a la forma española que comprueba el propio programa.

## Ejemplo histórico de salida (no garantizado)

```text
8 celdas RELAY_EARLY -> CONNECTED
Comprobación: CORRECTA
9 celdas RELAY_EARLY -> circuito destruido, motivo 1
Comprobación: CORRECTA
```

- Con **ocho**, el `BEGIN_DIR` del ejemplo recibió `CONNECTED`. No significa que todos los repetidores **deban aceptar** `DROP` dentro de `RELAY_EARLY`.
- Con **nueve**, la referencia observó `DESTROY` con motivo **1** (`PROTOCOL`). El texto normativo **SHOULD** no exige esa causa específica. Otra respuesta o un cierre anterior deja la prueba histórica sin reproducir, pero no constituye automáticamente una infracción del protocolo.
- El cupo es **por circuito**. Las extensiones de trayectos de varios saltos pueden consumirlo; aquí la construcción inicial **`CREATE2`** de un circuito de un salto elimina ese factor del experimento.

La demostración **no reproduce el ataque de señalización entrante del año 2014**, sino una inyección deliberadamente anómala en el sentido opuesto. Los repetidores participantes pueden ver el tipo exterior de la celda, pero un observador pasivo del enlace TLS cifrado no puede leerlo directamente.

## Pruebas y comprobación automática

La edición española incorpora `labs/es/laboratorio/test_relay_early.py`, que usa un **canal y un cifrado simulados** para comprobar el número de celdas, su comando exterior `RELAY_EARLY`, los casos permitidos y el criterio de evaluación. **No demuestra** la aceptación por un Tor real ni la corrección de la señalización de 2014.

```bash
PYTHONPATH=labs/es/codigo:labs/es/laboratorio python3 -m pytest -q labs/es/laboratorio/test_relay_early.py
```

La función **italiana** `scripts/verify_labs.py::lab17` compara únicamente dos líneas literales, `CONNECTED` y `distrutto, motivo 1`, **sin comprobar el código de salida del subproceso**. No verifica la totalidad de los requisitos de la especificación.

## Posibles problemas

| Síntoma | Comprobación |
|---|---|
| La prueba con 8 falla | `DROP` dentro de `RELAY_EARLY` es intencionadamente no conforme. Comprobar versión y registros del repetidor privado antes de atribuirlo solo al cupo. |
| La novena no da motivo 1 | `SHOULD` no exige ese código; registrar la reacción del Tor utilizado. |
| `CircuitError` al crear el circuito | Verificar Chutney, el repetidor `004r` y las rutas locales. No probar repetidores públicos. |

Referencias: [Tor Specification — RELAY_EARLY](https://spec.torproject.org/tor-spec/relay-early.html); [Tor Project — aviso del 30 de julio de 2014](https://blog.torproject.org/tor-security-advisory-relay-early-traffic-confirmation-attack/).
