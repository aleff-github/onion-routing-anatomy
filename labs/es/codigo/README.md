# torlab — cliente didáctico de Tor (entorno español)

El paquete Python `torlab` acompaña los laboratorios de *Anatomía de Tor*. Implementa de forma didáctica algunas partes del protocolo Tor real y está destinado **únicamente a la red privada de pruebas** descrita en [`../README.md`](../README.md). No es un cliente completo ni una herramienta para garantizar el anonimato.

## Comprobaciones previstas

Desde la **raíz del repositorio**, con Python 3.11+, `pytest` y `cryptography` instalados:

```bash
PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test
```

Este comando se limita a la suite unitaria del paquete español. El objetivo `make -C labs/es test` **también ejecuta comprobaciones adicionales** de `labs/es/laboratorio/`; no equivale a un test exclusivamente unitario ni debe interpretarse como prueba de interoperabilidad con la red Tor. La versión italiana del código, en `labs/it/codice/torlab/`, es independiente: sus resultados no se trasladan automáticamente a esta edición.

## Módulos del paquete

| Módulo | Lab. | Función |
|---|---:|---|
| `channel.py` | 1 | conexión TLS, celdas iniciales e identidad del repetidor |
| `cells.py` | 2 | celdas fijas, variables y mensajes relay |
| `ntor.py` | 3 | intercambios ntor y ntor-v3 |
| `encryption.py`, `circuit.py` | 4 | cifrado por capas y extensión de circuitos |
| `stream.py` | 5 | flujos y SENDME |
| `directory.py` | 6 | consenso, certificados y microdescriptores |
| `path_selection.py` | 7 | selección ponderada de rutas |
| `onion.py` | 8 | direcciones y descriptores onion v3 |
| `pow.py` | 9 | umbral Blake2b con soluciones Equi-X **simuladas** |
| `traffic.py` | 12 | interpretación de capturas TLS descifradas |
| `metrics.py` | 15 | estadísticas del consenso |
| `simulation.py` | 19 | simulación del tiempo hasta la primera exposición |
| `conversion.py` | Ap. B | conversión de claves y certificación cruzada |
| `laboratory.py` | auxiliar | nodos y puertos de la red privada |

Los demás laboratorios emplean, cuando corresponde, scripts separados en `../laboratorio/`. Los vectores criptográficos y documentos firmados se conservan **sin cambiar un solo byte**: no son prosa que deba traducirse. En particular, `pow.py` **no implementa Equi-X**; simula sus soluciones para estudiar la capa Blake2b.

## Alcance y seguridad

El cliente omite controles de congestión completos, rotación de circuitos, relleno y otras defensas contra el análisis del tráfico. **No lo utilices para proteger personas, transmitir datos sensibles ni experimentar con repetidores Tor públicos.** Para privacidad real utiliza versiones oficiales y actualizadas de Tor o Arti. Una red Tor privada no garantiza por sí misma el aislamiento del sistema anfitrión.