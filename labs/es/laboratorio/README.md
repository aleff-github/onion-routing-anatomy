# Red privada de Tor — Edición española

Aquí se ejecutará la red privada descrita en el capítulo 19 de *Anatomía de Tor*. **Nunca** se deben dirigir los experimentos a repetidores públicos.

Están disponibles el Dockerfile, los Makefile, las topologías Chutney y los scripts de los laboratorios 10, 11, 13, 14, 16, 17, 18 y 20, junto con sus pruebas offline.

## Primeros comandos

Desde la raíz del repositorio:

```bash
make -C labs/es/laboratorio image
make -C labs/es/laboratorio start
make -C labs/es/laboratorio verify   # comprueba la red Chutney, no todos los laboratorios
make -C labs/es/laboratorio status
make -C labs/es/laboratorio shell
make -C labs/es/laboratorio stop
make -C labs/es/laboratorio clean
```

Para el laboratorio 10, detén primero la topología ordinaria y comprueba el estado de `net/` antes de usar `make -C labs/es/laboratorio start NETWORK=book-bridge`. **`make clean` destruye las claves, identidades y el estado generados en `net/`; ejecútalo solo si son prescindibles.**

La imagen propia es `torbook-es-lab:latest` y el contenedor propio, `torbook-es-network`; así no se reutilizan los nombres de otras ediciones. **Los puertos del anfitrión siguen siendo compartidos** porque se utiliza `--network host`, sin aislamiento de red. El objetivo `preflight` solo intenta conectar por TCP/IPv4 a `127.0.0.1` en los puertos previstos; **no garantiza que estén libres todas las interfaces, ni descarta cambios posteriores**. Detén las demás redes de laboratorio antes de cambiar de idioma.

La topología `book` utiliza diez nodos en `127.0.0.1`: tres autoridades de directorio, tres repetidores intermedios, dos salidas, un cliente y un servicio onion. Para los roles aplicables, Chutney utiliza ORPort `5100+n` **en los repetidores**, ControlPort `8000+n` y SocksPort `9000+n` **en los clientes**; ni el cliente ni el servicio onion pasan a ser repetidores por su número de nodo.

El árbol `net/` se genera durante el arranque, contiene claves privadas de laboratorio y está excluido de Git. **No publicar las claves generadas.** Los resultados numéricos de la wiki proceden de la edición de referencia, no de pruebas de esta infraestructura.

## Laboratorio 10 — Puente obfs4

La topología Chutney `book-bridge` ya está disponible: tiene **12 nodos** y no incluye el servicio onion de `book`. El script `puente_obfs4.py` aporta verificaciones **limitadas a la red local**: lectura del registro del cliente 011bc, petición HTTP por SOCKS 9011 a `127.0.0.1:8080`, intento TLS de control contra `127.0.0.1:9909` y análisis de una captura guardada en `laboratorio/net/`.

```bash
make -C labs/es/laboratorio clean                 # borra net/ y sus claves; solo en una red desechable
make -C labs/es/laboratorio image                 # obligatorio si todavía no existe la imagen
make -C labs/es/laboratorio start NETWORK=book-bridge
make -C labs/es/laboratorio puente-estado
make -C labs/es/laboratorio puente-http
make -C labs/es/laboratorio puente-sondeo
make -C labs/es/laboratorio puente-captura ARCHIVO=b1.pcap
make -C labs/es/laboratorio verify               # verificación de red Chutney, no de todos los scripts
```

La comprobación HTTP requiere arrancar por separado un servidor local en el puerto 8080; la captura debe generarse antes de analizarla. **No ejecutar el sondeo contra puentes públicos**. El puerto 9909 está incluido ahora en la detección de conflictos previa al arranque.

Las pruebas offline del analizador se ejecutan con `make -C labs/es/laboratorio puente-pruebas`.

## Laboratorio 11 — Aislamiento de flujos con Stem

El archivo `aislamiento.py` reproduce el experimento del capítulo 18. Envía peticiones exclusivamente a `127.0.0.1:8080` por SOCKS `127.0.0.1:9008`, observa los eventos del ControlPort `127.0.0.1:8008` del cliente 008c y compara túneles lógicos con `CONFLUX_ID`. No contacta con repetidores públicos.

```bash
# Primero: red privada book activa y servidor web local en 127.0.0.1:8080.
make -C labs/es/laboratorio aislamiento
# Pruebas que no requieren contenedor ni red:
make -C labs/es/laboratorio aislamiento-pruebas
```

**No sirvas la raíz del repositorio con `python3 -m http.server`**, pues podría mostrar archivos de trabajo o material sensible. Para un servidor de demostración que exponga solo un archivo público, ejecútalo en otra terminal:

```bash
DIR_HTTP=$(mktemp -d)
printf 'Laboratorio privado Tor\n' > "$DIR_HTTP/index.html"
python3 -m http.server 8080 --bind 127.0.0.1 --directory "$DIR_HTTP"
```

Detén el servidor con Ctrl+C cuando termines; elimina esa carpeta temporal después de comprobar su contenido. No utilices este servidor mientras el laboratorio 18 ocupe el puerto 8080. El experimento comprueba reutilización con las mismas credenciales, aislamiento entre credenciales diferentes y cambio posterior a `NEWNYM`. Los resultados dependen de los circuitos disponibles.

## Laboratorio 13 — Descubrimiento restringido

El archivo `descubrimiento_restringido.py` crea un servicio onion adicional bajo `009h/restricted_service` y una clave X25519 efímera. Compara el acceso del cliente `008c` sin autorización y después de instalar `alice.auth_private`. Mantiene las rutas de protocolo `HiddenServiceDir`, `HiddenServicePort` y `ClientOnionAuthDir`; todo el tráfico utiliza la red privada y el servidor HTTP `127.0.0.1:8080`.

```bash
# Pruebas offline (host, con pytest y cryptography):
make -C labs/es/laboratorio descubrimiento-pruebas

# Experimento con Docker/Chutney book ya iniciados y HTTP local activo:
make -C labs/es/laboratorio descubrimiento
```

Antes de empezar, comprueba que no existan restos anteriores en `net/nodes/009h/restricted_service` o `net/nodes/008c/onion_auth`. **El programa se niega a sobrescribir esos directorios.** Si termina normalmente, restaura los dos `torrc` y elimina únicamente los archivos temporales que ha creado. Un cierre forzado puede impedir la limpieza automática y requiere revisión manual de la red prescindible.

## Laboratorio 14 — Política de salida

`politica_salida.py` prueba tres destinos locales a través de un circuito de tres saltos `003r → 005r → 006e`. Inserta de forma temporal una regla `ExitPolicy reject 127.0.0.1:8080`, comprueba el acceso al puerto permitido `8081` y observa la conexión al puerto sin servidor `9999`. Intenta restaurar el `torrc` de 006e también si falla la prueba; una interrupción forzada o un fallo de escritura/HUP puede requerir recuperación manual.

```bash
make -C labs/es/laboratorio politica-salida-pruebas
# Solo después de iniciar la red privada book:
make -C labs/es/laboratorio politica-salida
```

El resultado esperado para 9999 en la referencia Tor 0.4.9.13 era `END MISC`; una versión corregida podría devolver `END CONNECTREFUSED`. Las comprobaciones aceptan ambas razones sin ocultar el resultado observado.

## Laboratorio 16 — Correlación temporal sobre tráfico propio

`correlacion.py` envía ráfagas de seis clientes controlados mediante SOCKS local `127.0.0.1:9008` a un servidor del propio laboratorio enlazado a `127.0.0.1:8095`. Compara series temporales de entrada y salida con intervalos de 250 ms. Las correspondencias reales solo se utilizan para evaluar el resultado; el programa considera satisfactorios al menos cinco aciertos de seis.

```bash
make -C labs/es/laboratorio correlacion-pruebas
# Solo con Chutney book activo:
make -C labs/es/laboratorio correlacion SEMILLA=3
```

El puerto 8095 se comprueba al iniciar la red para evitar conflictos.

## Laboratorio 17 — Límite de RELAY_EARLY

`relay_early.py` construye circuitos privados de un salto al repetidor `004r` y compara el resultado de 8 y 9 celdas `RELAY_EARLY` que contienen mensajes `DROP`. El script restringe los valores a estos dos casos y no modifica el límite habitual de la API del cliente.

```bash
make -C labs/es/laboratorio relay-early-pruebas
# Solo con Chutney book iniciado:
make -C labs/es/laboratorio relay-early CANTIDADES='8 9'
```

La salida histórica era `CONNECTED` con ocho y destrucción con motivo de protocolo 1 con nueve; se trata de una **observación didáctica, no de un resultado garantizado por la especificación Tor**.

## Laboratorio 18 — Diagnóstico SOCKS y precauciones sobre DNS

`fuga_dns.py` contrasta `--socks5`, `--socks5-hostname` y `SafeSocks 1` contra el nombre local `localhost`. Los mensajes de `TestSocks` describen comportamientos SOCKS: **no son una prueba de fuga DNS real**. El script no solicita dominios externos. Inicia su propio servidor HTTP en `127.0.0.1:8080`, por lo que ese puerto debe estar libre. El script sirve únicamente una respuesta fija (no archivos del volumen `/lab`), desactiva expresamente `NO_PROXY` para obligar a utilizar SOCKS y exige los avisos correspondientes emitidos por Tor. La prueba `SafeSocks` solo se acepta si curl termina con un error y comunica `HTTP 000`. Intenta restaurar mediante Stem los valores originales de `TestSocks` y `SafeSocks` incluso ante errores; una pérdida del ControlPort puede impedir completar esa restauración.

```bash
make -C labs/es/laboratorio fuga-dns-pruebas
# Con la red book activa, desde el contenedor privado:
make -C labs/es/laboratorio fuga-dns
```

Las pruebas offline y los resultados del cliente privado siguen sin ejecutarse; el registro inglés sirve únicamente de referencia histórica.

## Laboratorio 20 — Configuración privada de Arti

`arti_config.py` lee las identidades RSA, Ed25519 y v3 de las tres autoridades de Chutney, y genera una configuración TOML para una instancia Arti con SocksPort 9150, direcciones locales, fallbacks privados y parámetros de pruebas. No descarga ni compila Rust.

```bash
make -C labs/es/laboratorio arti-config-pruebas
# Solo después de generar los nodos con Chutney book:
make -C labs/es/laboratorio arti-config
```

El archivo resultante queda en `labs/es/laboratorio/net/arti/arti.toml` (excluido de Git). La prueba de interoperabilidad requiere compilar Arti en `labs/es/vendor/arti`.
