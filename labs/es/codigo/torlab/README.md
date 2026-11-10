# torlab — Cliente didáctico de Tor (edición española)

Este paquete Python, pequeño y legible, acompaña los laboratorios de la **red privada** del libro. **No** es un cliente Tor de producción ni una herramienta para garantizar anonimato. No lo uses para proteger identidades reales ni dirijas los experimentos interactivos a repetidores públicos. Para un uso real, emplea Tor Browser o Arti. La infraestructura privada se documenta en [`../../laboratorio/`](../../laboratorio/README.md).

| Laboratorio | Capítulo | Módulo(s) | Contenido |
|---|---|---|---|
| 1 | 07 | `channel.py` | Canal TLS, VERSIONS, CERTS, NETINFO y comprobación de identidad |
| 2 | 08 | `cells.py` | Codificación de celdas fijas, variables y relay |
| 3 | 09 | `ntor.py` | CREATE_FAST, ntor/ntor-v3, CREATE2/CREATED2 y EXTEND2 |
| 4 | 10 | `encryption.py`, `circuit.py` | Cifrado por capas, resúmenes y construcción de circuitos |
| 5 | 11 | `stream.py` | BEGIN/DATA/END, SENDME y control de flujos |
| 6 | 12 | `directory.py` | Consenso, certificados, datos de repetidores y microdescriptores |
| 7 | 13 | `path_selection.py` | Selección ponderada de Guard/Middle/Exit |
| 8 | 14 | `onion.py` | Direcciones onion v3, cegado de claves, HSDir y descriptores |
| 9 | 15 | `pow.py` | Umbral Blake2b: **simulación sin Equi-X** |
| 12 | 20 | `traffic.py` | Lectura de celdas de una traza TLS ya descifrada |
| 15 | 24 | `metrics.py` | Estadísticas de red y estimaciones didácticas de usuarios |
| 19 | 29 | `simulation.py` | Modelo simplificado tipo TorPS de compromiso |
| Apéndice B | B | `conversion.py` | Conversión Montgomery/Edwards y certificados cruzados |
| Auxiliar | 19 | `laboratory.py` | Identidades y claves de la red privada |

### Ejecución de las pruebas

Desde la **raíz del repositorio**, una vez instaladas las dependencias de Python del proyecto en un entorno aislado:

```bash
PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test
```

En PowerShell:

```powershell
$env:PYTHONPATH = "labs/es/codigo"
python -m pytest -q labs/es/codigo/torlab/test
```

Los comandos sirven para reproducir el trabajo, **no indican que la suite haya superado las pruebas**. `test/data/` contiene documentos criptográficos y capturas de prueba: no se modifican sus bytes en la traducción. No se ejecutaron Python/pytest, Tor/Chutney/Docker ni compilaciones PDF/EPUB.

### Límites del protocolo y fuentes de datos

- **Laboratorio 7:** el selector emplea los pesos del consenso (`bwweightscale`), identidades de repetidores e IPv4 `/16`, pero no todas las familias, políticas de salida, restricciones IPv6 ni guardias persistentes. El consenso privado no sustituye un consenso público histórico.
- **Laboratorio 8:** se examinan firmas, cifrado y descriptores con vectores históricos. El analizador utiliza por defecto `check_expiration=False` para dichos ejemplos; para datos actuales hay que validar la caducidad y la autenticidad del directorio por separado. No incluye restricted discovery ni la comprobación completa de puntos de introducción.
- **Laboratorio 9:** `required_attempts()` genera **candidatos aleatorios de 16 bytes**, no soluciones Equi-X. Tras `max_attempts` (por defecto **10.000**) puede lanzar `RuntimeError`. Pasar el umbral Blake2b **no acredita** un PoW Tor válido.
- **Laboratorios 12, 15 y 19:** el análisis de tráfico, las métricas y las simulaciones requieren datos históricos correspondientes. Los ejemplos públicos necesitan conjuntos archivados y verificados por separado; las muestras privadas no los reemplazan. La simulación no garantiza el anonimato.

Las API, los nombres de campos, los bytes del protocolo y los vectores criptográficos no se traducen.

### Trazabilidad específica de la edición española

Los archivos de prueba criptográficos del laboratorio 6, incluidos los documentos firmados de `test/data/`, permanecen sin traducir ni alterar; la suite incluye una comprobación negativa del consenso.

Los ejemplos de selección de rutas del laboratorio 7 basados en la red privada no sustituyen el **consenso público fechado** que necesitan las estadísticas históricas de la wiki. Los vectores de descriptor del laboratorio 8 (`test/data/onion-descriptor.address` y `test/data/onion-descriptor.txt`) mantienen intactos sus datos firmados; los usa `test_onion.py`.

El laboratorio 12 conserva la captura textual `test/data/follow-tls.txt` y los identificadores técnicos `client`/`relay` sin traducción de sus bytes; esta edición no se ha contrastado todavía con una captura nueva. En el laboratorio 15, las estadísticas históricas de la wiki se relacionan con un consenso público de **23 de septiembre de 2026** conservado en CollecTor, distinto de la muestra privada: para reproducirlas se necesitan documentos y certificados coherentes con esa fecha. La preparación opcional es `make -C labs/es data`.

El laboratorio 19 usa una simulación TorPS simplificada; el escenario público de **9.358 repetidores** mencionado en la documentación requiere datos históricos descargados y validados por separado. Los experimentos ajenos al paquete `torlab` están documentados en `labs/es/laboratorio/` y en la wiki.
