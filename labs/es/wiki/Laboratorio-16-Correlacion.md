# Laboratorio 16 — Correlacionar tu propio tráfico

| | |
|---|---|
| **Capítulo** | 26 — Ataques contra la red |
| **¿Requiere la red?** | Sí, solo la red privada del libro |
| **Requisitos previos** | Chutney iniciado con el cliente Tor `008c` |
| **Duración** | 1–2 horas de estudio; 20 segundos de tráfico nominal |
| **Script** | `labs/es/laboratorio/correlacion.py` |

> **Utiliza exclusivamente tráfico sintético propio** generado en la red privada. Este laboratorio no implica analizar comunicaciones de terceros.

## Qué mide realmente

El programa abre **seis flujos TCP sintéticos simultáneos mediante una única instancia de cliente Tor**, `008c`, en el puerto SOCKS 9008. **No inicia seis clientes Tor independientes**. Cada flujo usa credenciales SOCKS distintas para solicitar contextos de aislamiento diferentes; esto **no garantiza** una ruta Tor separada e inmutable por cada flujo.

En el extremo emisor se registran tiempos después de `sendall` y, en el receptor, los tiempos de los datos que llegan mediante `recv` al **servidor de prueba controlado por nosotros**, en `127.0.0.1:8095`. **No se captura pasivamente el tráfico de un repetidor de salida**: el segundo punto de medida es el servidor de destino, y ambos relojes pertenecen a la misma máquina.

El emisor añade **cuatro bytes con un identificador en claro** al principio de cada conexión. El servidor lo guarda como respuesta conocida para **evaluar** las correspondencias, pero el cálculo de los coeficientes de Pearson **no utiliza ese identificador**. Como el servidor puede leerlo, la demostración **no prueba** que un observador desconocedor de las identidades pueda identificarlas a partir de los tiempos solamente.

## Preparación y ejecución

Desde la raíz del repositorio, construye la imagen antes del primer uso y arranca solo la red privada española: otras ediciones comparten puertos del anfitrión.

```bash
# Primera vez: make -C labs/es/laboratorio image
make -C labs/es/laboratorio start
make -C labs/es/laboratorio correlacion SEMILLA=3
```

El valor `3` es la **semilla** del generador seudoaleatorio. Reproduce las decisiones aleatorias, pero **no garantiza** repetir exactamente las marcas de tiempo, los índices de salida ni los coeficientes: intervienen la planificación de hilos, la segmentación y los búferes TCP y las demoras de circuitos. Se utilizan intervalos de **250 ms** durante **20 segundos nominales** de tráfico, más el tiempo necesario para conectar y limpiar.

## Ejemplo histórico (no garantizado)

```text
cliente 0: +0.24 -0.04 +0.09 +0.86 +0.00 -0.04  -> flujo de salida 3 CORRECTO
cliente 2: -0.03 +0.85 +0.35 -0.07 +0.13 -0.05  -> flujo de salida 1 CORRECTO
cliente 5: +0.87 -0.01 +0.27 +0.26 +0.05 +0.15  -> flujo de salida 0 CORRECTO
cliente 4: +0.09 +0.32 +0.85 -0.07 +0.02 +0.10  -> flujo de salida 2 CORRECTO
cliente 1: +0.24 -0.07 +0.19 +0.08 -0.03 +0.72  -> flujo de salida 5 CORRECTO
cliente 3: +0.17 +0.13 +0.04 +0.13 +0.70 +0.09  -> flujo de salida 4 CORRECTO
correspondencias correctas: 6/6
```

Cada fila presenta seis **coeficientes de correlación de Pearson** entre las cantidades de **bytes por intervalo** enviadas y las observadas por el receptor. No representan marcas de tiempo de paquetes obtenidas mediante una captura. El receptor numera los flujos según el orden de las conexiones; el orden y los valores pueden cambiar de una ejecución a otra.

El programa selecciona el **coeficiente máximo de manera independiente por cada flujo emisor**. **No calcula una correspondencia global uno a uno**: dos emisores pueden seleccionar un mismo flujo receptor. Una vez decidido el índice, la identificación conocida sirve solo para evaluar si el resultado es `CORRECTO` o `INCORRECTO`. Las series constantes, ausentes o incompatibles no permiten calcular una correlación útil.

La referencia muestra 6/6, pero el criterio didáctico acepta también 5/6. El script verifica que existen los seis flujos, propaga los fallos de hilos, completa la lectura de las respuestas SOCKS5 y rechaza series inservibles; devuelve un estado distinto de cero si obtiene menos de cinco aciertos. **No se ha vuelto a ejecutar con Tor.**

## Qué no demuestra

La prueba no mide una tasa de éxito contra usuarios reales. Para intentar una correlación en Internet se necesitan dos posiciones de observación apropiadas, sincronización temporal, muestras suficientes y tratamiento del ruido, las variaciones de red y los falsos positivos. Los guardias persistentes ([laboratorio 19](Laboratorio-19-Simulacion.md)) reducen la exposición a nuevas entradas, pero no eliminan el riesgo si ya se observan los dos extremos.

## Pruebas offline y validación

La edición española incluye `test_correlacion.py`, basado en **series fabricadas**, que comprueba la formación de intervalos, correlaciones positivas/negativas, rechazo de series constantes y restricciones de destinos locales:

```bash
PYTHONPATH=labs/es/laboratorio python3 -m pytest -q labs/es/laboratorio/test_correlacion.py
```

La comprobación **italiana** `scripts/verify_labs.py::lab16` acepta `5/6` o `6/6` en la última línea, pero **no verifica el código de salida del subproceso**. Los tests sintéticos no sustituyen una captura de red ni un estudio estadístico de múltiples ejecuciones.

## Problemas conocidos

| Síntoma | Comprobación |
|---|---|
| Menos de cinco aciertos | Ritmos demasiado parecidos; repetir en la red privada registrando la semilla y la carga. |
| Error SOCKS5 o faltan flujos | Comprobar el cliente `008c`, puerto 9008, negociación SOCKS5 y servidor de prueba. |
| Serie constante o incompleta | El programa rechaza el caso y no inventa una correspondencia. |
| `Address already in use` | El puerto 8095 está ocupado por otro proceso de prueba; detener solo el propio. |

