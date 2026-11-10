# Resolución de problemas

Cada entrada de esta página describe un problema encontrado realmente en la red de laboratorio, junto a su causa. No son diagnósticos válidos para cualquier versión. El contenedor usa `--network host` y comparte puertos con las demás ediciones.

Las rutas y los nombres de contenedor corresponden a `labs/es/`.

## La red no se inicia

**`docker: Error response from daemon: Conflict. The container name "torbook-es-network" is already in use`**  
El contenedor ya existe, aunque esté detenido. Comprueba con `docker ps -a` que `torbook-es-network` pertenece a **tu red de laboratorio desechable** y solo entonces ejecuta `make -C labs/es/laboratorio stop`. La edición inglesa utiliza otro nombre de contenedor, pero **no otros rangos de puertos**.

**El arranque no finaliza; los nodos se quedan en el 5 %**  
Las causas posibles son puertos ocupados, autoridades inaccesibles o procesos que quedaron activos. **No ejecutes `pkill -x tor` sin inspección previa:** cerraría todos los procesos Tor del contenedor. Empieza con comprobaciones que no modifican nada:

```bash
docker ps -a
ss -ltnp | grep -E ':(510[0-9]|710[0-9]|800[0-9]|900[0-9])' || true
```

Si confirmas que `torbook-es-network` es exclusivamente el laboratorio desechable español, usa `make -C labs/es/laboratorio stop` y vuelve a iniciarlo con `make -C labs/es/laboratorio start`. Evita `pkill -f "tor -f"`, que puede afectar a la propia consola; incluso `pkill -x tor` no distingue nodos.

**Los nodos parecen activos, pero no responden**  
Tras un cierre abrupto pueden quedar archivos `pid` obsoletos. El target italiano `make riavvia` opera sobre **otro contenedor**, por lo que no debe usarse en español. El Makefile español no define un `restart` propio; si necesitas reconstruir la red, **verifica primero que puedes perder las claves y el estado** y ejecuta:

```bash
make -C labs/es/laboratorio clean
make -C labs/es/laboratorio start
```

`clean` borra todo `labs/es/laboratorio/net/`. El arranque de Chutney incluye una segunda fase (`CHUTNEY_LAUNCH_PHASE=2`) para los clientes y el servicio onion.

**`chutney verify` falla con `Address already in use`**  
Otra aplicación ocupa un puerto. Además de los servidores web 8080/4747, revisa los puertos de nodos Tor (ORPort, ControlPort y SOCKS) que comparten todas las ediciones:

```bash
ss -ltnp | grep -E ':(8080|4747|9008)'
```

## Diferenciar pruebas offline y verificaciones de red

```bash
PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test
```

Esta suite verifica módulos Python y datos guardados, **no inicia Tor ni un servidor HTTP en el puerto 8080**. La orden `make -C labs/es/laboratorio verify` ejecuta `chutney verify` contra la topología activa. El `make verifica-lab` italiano es otro verificador, ligado a `laboratorio/`; **no valida automáticamente la traducción española**. El error `cannot bind port 8080` puede corresponder a un experimento de red que intente abrir un servidor propio, no a esta suite offline.

**Falla un experimento de red**  
Comprueba `make -C labs/es/laboratorio status` y, si existen, los registros `000a/notice.log` y `008c/notice.log`. Los tests offline no requieren la red.

**Un laboratorio falla una vez y funciona al repetirlo**  
La red tiene solamente tres repetidores intermedios, así que la construcción de circuitos puede fallar temporalmente. `CREATE2 rejected (command 4)` significa que llegó una celda `DESTROY`. Conserva primero los registros. Un nuevo intento puede orientar el diagnóstico, pero **el éxito ocasional no demuestra que no exista un defecto**.

**Solo los laboratorios 7, 15 y 19 fallan en las comprobaciones numéricas**  
Esas comprobaciones numéricas son propias del **verificador italiano de la raíz**, que utiliza el consenso del **23 de septiembre de 2026** de `fonti/collector/`; **no forman parte de la ejecución ordinaria de pytest español**. Cuando falta ese archivo, el verificador italiano informa **SKIP**, no PASS. Para reproducir las cifras por separado en español, primero descarga el consenso mediante `make -C labs/es data`.

## Laboratorios concretos

**El servicio onion deja de responder; los registros muestran `400 Invalid HS descriptor`**  
En la referencia se observó un directorio `authorized_clients` vacío, pero `400 Invalid HS descriptor` **no es un diagnóstico universal**. La protección **solo se activa si Tor carga al menos un archivo `.auth` válido**, con el formato `descriptor:x25519:<clave-pública-base32>`. Si no se activa, quien conozca la dirección podría acceder al servicio. Tras una interrupción del [laboratorio 13](Laboratorio-13-Descubrimiento-restringido.md), inspecciona primero `torrc`, el directorio y los archivos sin borrar nada.

El script envía HUP **solo al PID comprobado del nodo** y trata de restaurar los dos `torrc`; si no puede confirmar la recarga, conserva las claves temporales para inspección manual. **No uses** el antiguo `pkill -HUP -f 009h/torrc`, ni borres un directorio cuya relación con la red desechable no hayas verificado. Comienza por una inspección de solo lectura:

```bash
ls -la labs/es/laboratorio/net/nodes/009h/restricted_service/authorized_clients/
grep -nE 'HiddenServiceDir|HiddenServicePort' labs/es/laboratorio/net/nodes/009h/torrc
```

Si el estado es irrecuperable y **todos los datos pueden eliminarse**, reconstruye solamente la red de pruebas con `clean` y `start`. **Jamás apliques ese procedimiento a un servicio onion real.**

**El cliente deja de funcionar después de modificar `torrc`**  
Una opción como `ClientOnionAuthDir` o `HiddenServiceDir` contiene una ruta del **anfitrión**, pero tor la interpreta **dentro** del contenedor. Esto provoca un error de configuración. Deriva las rutas internas del `DataDirectory` del nodo.

**Una salida devuelve `END TORPROTOCOL` para todas las solicitudes**  
Estás utilizando un circuito de **un solo salto**. Una salida se niega a reenviar tráfico externo desde ese circuito, porque se convertiría en un proxy abierto. Construye un circuito de tres saltos.

**`LookupError: no microdescriptor for 003r`**  
El cliente todavía no ha descargado los microdescriptores. Espera aproximadamente un minuto tras el arranque.

**`the relay has a different identity from the expected one`, aunque el puerto es correcto**  
Se ha regenerado la red y, por tanto, se han generado claves nuevas. Cada limpieza de `labs/es/laboratorio/net/` cambiará las identidades. Vuelve a leer `fingerprint-ed25519`.

**El archivo pcap está vacío o `tshark` no consigue descifrarlo**  
Posibles causas, **sin un orden de frecuencia demostrado**: captura tardía, permisos insuficientes para `tcpdump` o `SSLKEYLOGFILE` configurado **después** de crear el socket TLS. No todos los procesos Tor o bibliotecas TLS ofrecen claves de sesión exportables para descifrar la captura.

## Restaurar el estado inicial

La red de prueba debe ser desechable. Si el estado es difícil de diagnosticar, suele ser más sencillo comenzar desde cero:

```bash
make -C labs/es/laboratorio clean
make -C labs/es/laboratorio start
make -C labs/es/laboratorio verify
PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test
```

**Advertencia:** `clean` eliminará los datos y las claves de prueba de `labs/es/laboratorio/net/` cuando se haya creado la red española. Comprueba previamente que esta carpeta contiene únicamente el estado de laboratorio desechable y no datos que necesites conservar.

Las cifras `successes:4 failures:0` y **53/53** corresponden a ejecuciones históricas de referencia; **no garantizan** el resultado de la edición española actual. Hay que distinguir PASS, FAIL y SKIP reales.

## Si tu problema no aparece aquí

Cada nodo tendrá su registro `labs/es/laboratorio/net/nodes/<nodo>/notice.log`. El del cliente suele ser especialmente útil. Para detalles adicionales, examina `info.log` si el nodo está configurado para generarlo.

Cuando un resultado experimental no coincide con lo previsto, busca un punto de comprobación intermedio y compara con una implementación de referencia. El cliente `tor` ejecutado dentro del laboratorio tiene un puerto de control, responde a `GETINFO` e implementa casi todo lo que intenta hacer el cliente experimental, pero ha sido probado mucho más extensamente.
