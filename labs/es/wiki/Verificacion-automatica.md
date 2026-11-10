# Verificación automática

El entorno de laboratorio español tiene sus fuentes y scripts en `labs/es/`. Las pruebas Python offline, la verificación de Chutney y los laboratorios dinámicos deben evaluarse por separado. El contenedor usa Docker `--network host`, con puertos compartidos entre idiomas.

El repositorio contiene el Dockerfile, el Makefile, las topologías privadas, los módulos didácticos de los laboratorios 1–9, 12, 15 y 19 y scripts especializados para los laboratorios 10, 11, 13, 14 y 16–18. El generador de configuración de Arti del laboratorio 20 no requiere compilar Rust. Las cifras de referencia proceden de las ejecuciones de la edición original italiana.

## Comandos principales

Desde la raíz del repositorio (la primera vez, crea la imagen con acceso a Internet):

```bash
PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test
make -C labs/es/laboratorio image       # primera vez: obtiene Tor, Chutney y dependencias
make -C labs/es/laboratorio start
make -C labs/es/laboratorio verify
make -C labs/es/laboratorio status
```

La primera orden ejecutará pruebas unitarias y de regresión del cliente educativo `torlab` con datos locales; **no inicia Tor ni un servidor HTTP en el puerto 8080**. Los resultados y el número de tests solo se conocerán al ejecutar la suite. La segunda iniciará la topología privada `book`. La tercera utilizará Chutney para comprobar la comunicación de extremo a extremo de la topología activa. La cuarta mostrará el estado de los nodos.

## Pruebas de código

El conjunto de pruebas de `torlab` está en `labs/es/codigo/torlab/test/`, junto con las pruebas offline de los laboratorios 10, 11, 13, 14, 16 y 17 bajo `labs/es/laboratorio/`. Las pruebas unitarias no necesitan acceder a la red Tor pública.

Sus principales categorías incluyen:

- **Pruebas de formato** de celdas, canales, documentos de directorio y mensajes relay.
- **Vectores criptográficos**, incluidos los de la propuesta 332 para ntor-v3 y los de la propuesta 216 para ntor HKDF.
- **Pruebas negativas** con firmas modificadas, valores de autenticación incorrectos, certificados caducados, longitudes malformadas e identidades incompatibles.
- **Pruebas de reproducibilidad** de los cálculos empleados en el libro.

Una prueba positiva que se supera no basta: un verificador que aceptara cualquier entrada también la superaría. Por eso es fundamental mantener los casos negativos y asegurarse de que se rechazan realmente.

En esta edición, `make -C labs/es test` ejecuta las 91 pruebas de `torlab` y las pruebas offline de los scripts de los laboratorios.

## Verificación de la red privada

**Construye primero la imagen** (`make -C labs/es/laboratorio image`) si aún no existe y evita conflictos con las demás redes lingüísticas:

```bash
make -C labs/es/laboratorio start
make -C labs/es/laboratorio verify
```

El objetivo `verify` ejecutará Chutney contra la topología activa; **no ejecuta los scripts de los veinte laboratorios ni la suite Python**. El entorno debe estar arrancado y las conexiones deben limitarse a la red privada.

Los scripts de `labs/es/laboratorio/` abarcan el puente obfs4 (laboratorio 10), el aislamiento de flujos con Stem (laboratorio 11) y el descubrimiento restringido (laboratorio 13), además de la política de salida (laboratorio 14), la correlación de tráfico propio (laboratorio 16) y el límite RELAY_EARLY (laboratorio 17). El experimento de advertencias DNS del laboratorio 18 también está en esa carpeta.

Ejemplos de rutas:

```bash
PYTHONPATH=labs/es/codigo python3 labs/es/laboratorio/politica_salida.py
python3 labs/es/laboratorio/descubrimiento_restringido.py
PYTHONPATH=labs/es/codigo python3 labs/es/laboratorio/relay_early.py 8 9
```

Las rutas de los laboratorios 13, 14 y 17 también existen en español. Para las pruebas offline de las herramientas ya incorporadas: 

```bash
make -C labs/es/laboratorio puente-pruebas
make -C labs/es/laboratorio aislamiento-pruebas
make -C labs/es/laboratorio descubrimiento-pruebas
make -C labs/es/laboratorio politica-salida-pruebas
make -C labs/es/laboratorio correlacion-pruebas
make -C labs/es/laboratorio relay-early-pruebas
make -C labs/es/laboratorio fuga-dns-pruebas
make -C labs/es/laboratorio arti-config-pruebas
# Solo con la red privada activa y un servidor HTTP local:
make -C labs/es/laboratorio aislamiento
```



## Topología de puentes

El laboratorio 10 utiliza la topología `book-bridge`, independiente de `book`:

```bash
make -C labs/es/laboratorio clean
make -C labs/es/laboratorio start NETWORK=book-bridge
make -C labs/es/laboratorio verify
```

Al finalizar:

```bash
make -C labs/es/laboratorio clean
make -C labs/es/laboratorio start
```

El objetivo `verify` no cambia la topología por sí mismo: comprueba la red que esté en funcionamiento. **Ambos comandos `clean` eliminan por completo `labs/es/laboratorio/net/`, incluidas claves privadas, identidades onion y resultados guardados.** La topología alternativa tiene 12 nodos, sin el servicio onion ordinario `009h`.

## Interpretar los fallos

| Síntoma | Posible explicación |
|---|---|
| Un experimento de red falla una vez y funciona al repetirlo | Guarda los registros e investiga: un éxito al repetirlo no demuestra por sí solo la ausencia de problemas. |
| El mismo paso falla siempre | Trátalo como una regresión real hasta comprender su causa. |
| Fallan todos los experimentos de red | Comprueba el estado de los nodos y los registros de las autoridades bajo `labs/es/laboratorio/net/nodes/`. |
| Una prueba criptográfica negativa se supera inesperadamente | Detente e investiga: el verificador podría aceptar entradas inválidas. |
| Difieren los cálculos basados en una instantánea pública | Confirma que utilizas el mismo consenso archivado y la misma fecha de referencia. |

## Antes de publicar una versión

Como mínimo, ejecutar:

```bash
PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test
make -C labs/es/laboratorio start
make -C labs/es/laboratorio verify
```

Después, repetir cada script cuyo resultado se cite en el libro, comprobando **códigos de salida, registros y efectos observados**; ni pytest ni Chutney `verify` comprueban automáticamente los veinte laboratorios. Los valores que dependen del tiempo, de claves nuevas de servicios onion, del consenso activo o de capturas de paquetes pueden diferir legítimamente. La estructura del protocolo y las invariantes comprobadas deben seguir coincidiendo.

El entorno español no debe dirigir a los lectores a árboles italianos como `labs/it/codice/`, `labs/it/laboratorio/` o `scripts/`, ni depender de directorios de ejecución de otras ediciones. Los objetivos italianos `make verifica-lab` y `make verifica-lab-bridge` verifican los laboratorios de la edición original, no el código de la edición española.
