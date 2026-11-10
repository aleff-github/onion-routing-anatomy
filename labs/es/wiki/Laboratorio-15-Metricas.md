# Laboratorio 15 — Estadísticas de la red a partir de un consenso

| | |
|---|---|
| **Capítulo** | 24 — Medir la red: Tor Metrics |
| **¿Requiere la red?** | No para calcular; sí para descargar inicialmente los datos históricos |
| **Requisitos previos** | Laboratorios 6 y 7 |
| **Duración** | Aproximadamente una hora de implementación; un minuto para repetir la ejecución |
| **Módulo** | `labs/es/codigo/torlab/metrics.py` |

## Qué demuestra

**Parte** de las estadísticas publicadas por [Tor Metrics](https://metrics.torproject.org/) —número de repetidores, indicadores y pesos consensuados de ancho de banda— se puede reconstruir a partir de un consenso firmado. **El número de usuarios no puede calcularse únicamente con ese consenso:** exige estadísticas agregadas de solicitudes a directorios procedentes de descriptores *extra-info*, una estimación de cobertura y una frecuencia media hipotética. Es una **estimación de presencia media diaria**, no un recuento de personas distintas.

## Preparación

Igual que en el [laboratorio 7](Laboratorio-07-Rutas.md), el ejemplo numérico necesita el consenso público del **23 de septiembre de 2026, a las 15:00 UTC**. El módulo y sus pruebas están en Git, pero **el archivo público no está versionado**. Desde la raíz del repositorio, la descarga explícita del archivo de CollecTor se solicita mediante:

```bash
make -C labs/es data
```

Esto prepara `labs/es/datos/collector/consensus-microdesc-2026-09-23-15`. Comprueba el encabezado y la fecha del documento. Las pruebas offline emplean en cambio el pequeño consenso de la red **privada** de `labs/es/codigo/torlab/test/data/`, que no reproduce las cifras de la red pública.

Para verificar las firmas también se necesitan los certificados de las autoridades. El procedimiento de referencia los descarga de esta manera:

```bash
curl -o labs/es/datos/collector/certs 'https://collector.torproject.org/recent/relay-descriptors/certs'
```

Comprueba que lo descargado no sea un índice HTML ni una página de error. En un documento bruto la primera línea significativa es `dir-key-certificate-version 3`; con anotaciones de CollecTor puede aparecer antes `@type ...`. La ruta `recent` **no garantiza** que las claves sean válidas para la fecha de septiembre de 2026: para reproducir firmas históricas hacen falta certificados de la época, no necesariamente los actuales.

## Ejecutar el experimento

Interfaz de línea de órdenes prevista:

```bash
export PYTHONPATH=labs/es/codigo
python3 -m torlab.metrics labs/es/datos/collector/consensus-microdesc-2026-09-23-15
```

## Resultado histórico de referencia (no revalidado)

```text
relay: 9358
flag: {'Running': 9358, 'Valid': 9358, 'Fast': 8961, 'Stable': 8199, 'V2Dir': 7674,
       'Guard': 5306, 'HSDir': 4050, 'Exit': 3177, 'BadExit': 32, 'MiddleOnly': 28,
       'StaleDesc': 21, 'Authority': 10}
total_bandwidth: 198927900
exit_bandwidth_share: 0.3308947161257923
guard_bandwidth_share: 0.7010271560701139
versions: [('Tor 0.4.9.12', 6027), ('Tor 0.4.9.11', 2520), ('Tor 0.4.9.9', 269), ...]
networks16: [('64.65', 771), ('192.42', 636), ('204.8', 598), ...]
```

Se conserva esta salida literal como referencia histórica del programa inglés; **no es una nueva ejecución del módulo español**. Los números se refieren exclusivamente a la instantánea del 23 de septiembre de 2026.

Interpretación:

- En el consenso histórico hay **3177** repetidores con el indicador `Exit`, pero `exit_bandwidth_share` suma solo los que tienen `Exit` **sin `BadExit`**. Las cuotas de alrededor del **33 %** (salidas) y del **70 %** (guardias) son **fracciones de la suma de valores `Bandwidth=` del consenso**: **no son cuotas de tráfico realmente transferido ni probabilidades finales de selección de circuitos**. Ambas categorías pueden solaparse; la ponderación por posición del [laboratorio 7](Laboratorio-07-Rutas.md) es un cálculo distinto.
- El resumen histórico cuenta **10** entradas con indicador `Authority`, mientras que la verificación de firmas se basa en **9** identidades de autoridades votantes. **Contar el indicador no identifica a los firmantes**. Para atribuir la décima entrada a la autoridad de puentes habría que contrastar identidades y documentos históricos, no basta con la diferencia numérica.
- `BadExit` y `MiddleOnly` restringen las funciones que puede desempeñar un repetidor; **no prueban por sí solos** que sea malicioso o esté comprometido.
- Algunas redes IPv4 **/16** contienen cientos de repetidores: esto indica concentración de direcciones, **no demuestra que tengan un mismo operador** ni que todos sean salidas. La separación por /16 es una de varias restricciones de selección de rutas.

Los recuentos se ordenan primero por valor y luego por nombre cuando hay empates. Sin ese criterio determinista, la iteración sobre conjuntos de Python podría variar el orden impreso incluso con los mismos números.

## Estimar usuarios

```bash
python3 - <<'EOF'
from torlab.metrics import estimate_users, remove_rounding
print(estimate_users(20_000_000, 0.6))  # ejemplo hipotético: 20 M de solicitudes comunicadas y cobertura del 60 %
EOF
```

Resultado de referencia:

```text
3333333
```

El ejemplo es **aritmético e hipotético**: `floor(20_000_000 / 0.6 / 10) = 3_333_333`. **El código no extrae veinte millones de solicitudes del consenso.** La metodología Tor Metrics utiliza estadísticas agregadas de solicitudes de los descriptores *extra-info*, ajusta según la fracción estimada `frac` y presupone **10 solicitudes de directorio por cliente medio y día**. La función devuelve `None` si `frac < 0.10` o `frac > 1.10`, permitiendo un ligero exceso sobre el 100 % por diseño. El resultado aproxima **presencia media**, no personas únicas. Los recuentos publicados se redondean para preservar la privacidad: la corrección `remove_rounding` es una función aparte **que no se invoca automáticamente** en este ejemplo.

## Verificar firmas

```bash
python3 - <<'EOF'
from torlab.directory import parse_consensus, parse_certificates, verify_consensus
c = parse_consensus(open("labs/es/datos/collector/consensus-microdesc-2026-09-23-15").read())
cert = parse_certificates(open("labs/es/datos/collector/certs").read())
print(verify_consensus(c, cert, 9)[:2])
EOF
```

Resultado de referencia:

```text
(9, 5)
```

La pareja `(9, 5)` es el resultado de referencia. Los archivos públicos no se guardan en el repositorio: descárgalos primero con `make -C labs/es data`. Si obtienes `(0, 5)`, comprueba posibles respuestas HTML, **certificados y claves firmantes incompatibles con la fecha**, la anotación `@type ...` de CollecTor y el intervalo exacto de bytes firmados. No debe confundirse una diferencia de certificados con una falsificación del consenso.

## Pruebas reproducibles con los datos archivados del laboratorio

El código del laboratorio 15 puede probarse sin red con el pequeño consenso privado `labs/es/codigo/torlab/test/data/consensus-microdesc.txt`. Es un **vector técnico de pruebas** conservado sin traducir, **no** el consenso público que contenía 9358 repetidores.

```bash
PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test/test_metrics.py
```

Se comprueban la aritmética de `estimate_users`, los límites de `fraction`, la corrección de redondeo de `remove_rounding` y el orden reproducible de los indicadores.

Para reproducir exactamente el registro de 9358 repetidores y la verificación histórica `(9, 5)` hacen falta **el consenso de esa fecha y los certificados de sus autoridades**. Los certificados de la red privada no son sustitutos de los públicos, ni un índice HTML descargado por error constituye un certificado.

`summary` mantiene sin traducir las claves de retorno (`relay`, `flag`, `total_bandwidth`, `exit_bandwidth_share`, `guard_bandwidth_share`, `versions`, `networks16`) por compatibilidad con el código, los tests y el laboratorio 7. El texto dirigido al lector sí se presenta en español.

## Verificación automática

El verificador **italiano** `scripts/verify_labs.py::lab15` comprueba conteos y proporciones correspondientes a **una instantánea pública fija**, la aritmética de una estimación **hipotética** y las firmas de ese consenso si se proporciona un archivo `certs`. No reconstruye las estadísticas reales de usuarios actuales. El test localizado `test_metrics.py` cubre el vector privado, los cálculos y el orden determinista; la comparación con el consenso público y las nueve firmas históricas requiere los datos descargados con `make -C labs/es data`.

## Problemas conocidos

- **`valid signatures: (0, 5)`**: comprueba la anotación `@type`, que `certs` no sea HTML y especialmente las **fechas y las identidades de los certificados firmantes**.
- **Las estadísticas numéricas difieren**: otro consenso produce valores diferentes. Para obtener los números de referencia se necesita exactamente el documento del 23 de septiembre de 2026.

 La instantánea pública fechada y los certificados históricos no se guardan en el repositorio: `make -C labs/es data` los descarga en `labs/es/datos/collector/`.

Referencias: [Tor Metrics — Reproducible Metrics](https://metrics.torproject.org/reproducible-metrics.html) y [Tor directory specification](https://spec.torproject.org/dir-spec/).
