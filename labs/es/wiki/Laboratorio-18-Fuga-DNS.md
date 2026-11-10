# Laboratorio 18 — Tor detecta un indicio de filtración DNS

| | |
|---|---|
| **Capítulo** | 28 — Errores de seguridad operativa |
| **¿Requiere la red?** | Sí |
| **Requisitos previos** | Red de laboratorio en funcionamiento |
| **Duración** | Aproximadamente 1 hora |
| **Script** | `labs/es/laboratorio/fuga_dns.py` |

## Qué demuestra

Uno de los errores más sencillos al configurar manualmente aplicaciones para utilizar Tor consiste en permitir que la **aplicación resuelva los nombres de host localmente**, en lugar de entregárselos a tor. La conexión TCP posterior puede seguir atravesando Tor, lo que produce la impresión de que todo está protegido, aunque una resolución previa podría haber expuesto el dominio fuera del circuito Tor; la consulta externa no es inevitable ni tiene por qué estar en claro.

El laboratorio también demuestra que tor puede **detectar el indicio de riesgo** cuando está configurado para hacerlo.

## Preparación

Desde la raíz del repositorio, construye la imagen la primera vez (`make -C labs/es/laboratorio image`) y no arranques varias redes lingüísticas simultáneamente.

La edición española incorpora el script y la infraestructura, todavía sin ejecutar. El propio script inicia un servidor de prueba limitado a `127.0.0.1:8080` que devuelve una respuesta fija, sin exponer archivos de `/lab` (no inicies otro servidor en ese puerto):

```bash
make -C labs/es/laboratorio start
```

El script se ejecuta dentro del contenedor porque utiliza `stem` para recibir advertencias del ControlPort del cliente. La imagen y el punto de montaje `/lab` están configurados:

```bash
make -C labs/es/laboratorio fuga-dns
```

## Ejemplo histórico esquemático (no garantizado)

Los mensajes de Tor se truncan a 110 caracteres y pueden variar entre versiones. El script español imprime **tres líneas de observación y otras tres líneas de comprobación**. Las siguientes son salidas **esquemáticas**, no una transcripción exacta garantizada:

```text
--socks5           HTTP 200  tor: ... only an IP address ...
--socks5-hostname  HTTP 200  tor: ... DNS resolution itself if necessary ...
--socks5 SafeSocks HTTP 000
Comprobación resolución local: CORRECTA
Comprobación resolución delegada: CORRECTA
Comprobación bloqueo SafeSocks: CORRECTA
```

Estos son mensajes literales de tor tal como se registraron en el experimento inglés. Su interpretación en español es:

- **`--socks5`** hace que curl resuelva el nombre localmente y entregue a tor **solo una dirección IP**. La solicitud HTTP sigue funcionando en el entorno controlado; por eso este error puede pasar inadvertido. El script activa temporalmente `TestSocks 1` para que tor avise de una solicitud con solo IP, que por sí sola no demuestra que se hayan filtrado consultas DNS.
- **`--socks5-hostname`** transmite el **nombre de host** mediante SOCKS y permite resolverlo del lado de la salida. Es el comportamiento recomendado.
- Con **`SafeSocks 1`**, tor rechaza la solicitud que solo contiene una IP, en lugar de limitarse a advertir. curl muestra `000` porque no se ha establecido ninguna conexión HTTP.

Por tanto, unos pocos caracteres de una opción de línea de comandos determinan dónde se resuelve un nombre. Es una razón por la que los usuarios deberían preferir Tor Browser a configurar manualmente aplicaciones arbitrarias.

> **Limitación importante.** El laboratorio utiliza deliberadamente `localhost`, que se resuelve a una dirección de bucle local sin consultar servidores DNS externos. Durante el experimento **no sale ninguna consulta DNS real del equipo**. Se demuestra el mecanismo: con `--socks5`, la aplicación resuelve el nombre antes de hablar con tor, de manera que tor solo recibe una IP. Sustituir `localhost` por un dominio ordinario podría causar una consulta externa, quizá en claro según la configuración DNS; esta prueba de red privada evita expresamente hacerlo.

## Tres opciones relevantes de tor

| Opción | Efecto |
|---|---|
| `TestSocks 1` | Registra qué forma de solicitud SOCKS observó tor. Solo diagnóstico. |
| `SafeSocks 1` | Rechaza solicitudes que proporcionan una dirección IP en vez de un nombre de host. |
| `WarnUnsafeSocks` | Emite advertencias; está habilitada por defecto en la configuración del código fuente. |

Ninguna de estas opciones puede impedir una consulta DNS que se haya realizado **antes** de que la aplicación contacte con tor. Solo pueden reaccionar al formato de la solicitud que recibe tor.

**Seguridad y recuperación.** El script español ya utiliza un servidor de respuesta fija para no exponer archivos de `/lab` y devuelve un error si el puerto 8080 está ocupado. Guarda los ajustes previos de Tor y los restaura en `finally`, valida los mensajes y los códigos de salida de curl y aplica `--noproxy ''`. Este código tampoco captura paquetes DNS, por lo que **no acredita la ausencia absoluta de consultas**. Las pruebas offline son independientes de una validación con Tor real.

## Restauración de configuración y pruebas offline

El script utiliza `localhost` de manera deliberada: **no consulta nombres externos** y no desencadena tráfico DNS real. Activa temporalmente `TestSocks` y `SafeSocks` mediante Stem, guarda sus valores previos y los restaura en un bloque `finally` aunque falle curl o alguna observación. Si un proceso se termina abruptamente, el bloque `finally` podría no ejecutarse y habrá que revisar los valores del cliente de prueba.

Las comprobaciones offline no precisan Tor, Docker ni Stem:

```bash
PYTHONPATH=labs/es/laboratorio python3 -m pytest -q labs/es/laboratorio/test_fuga_dns.py
```

Los tests comprueban las únicas opciones de curl permitidas, el destino local, los códigos HTTP, **el código de salida de curl**, el diagnóstico observado mediante ControlPort y el restablecimiento de las opciones de Tor también cuando hay errores. El comando fuerza `--noproxy ''` para que `NO_PROXY` del entorno no permita evitar el proxy SOCKS. El resultado se considera correcto solo cuando Tor emite el aviso esperado para cada formato SOCKS y la tercera solicitud falla con código HTTP `000` y salida no nula de curl. Estas pruebas aisladas no demuestran que una versión concreta de Tor haya emitido realmente los avisos.



## Verificación automática

La comprobación **italiana** `scripts/verify_labs.py::lab18` compara líneas y fragmentos literales sin verificar el código de salida del proceso; puede fallar por cambios de redacción en Tor. La versión española exige tanto los dos avisos específicos de Tor como el rechazo de `SafeSocks`.

## Problemas conocidos

| Síntoma | Causa |
|---|---|
| No aparece ninguna advertencia | El script podría no haber activado `TestSocks` mediante `SETCONF` en ControlPort. |
| La tercera prueba devuelve `200` | No se aplicó correctamente `SafeSocks`. |
| Las tres pruebas devuelven `HTTP 000` | El servidor de prueba no puede atender las conexiones o el cliente Tor no está funcionando. |
