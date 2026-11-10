# Laboratorio 13 — Un servicio onion con descubrimiento restringido

| | |
|---|---|
| **Capítulo** | 21 — Publicar un servicio onion |
| **¿Requiere la red?** | Sí |
| **Requisitos previos** | Laboratorio 8 |
| **Duración** | Entre 1 y 2 horas |
| **Script incorporado (sin validación dinámica)** | `labs/es/laboratorio/descubrimiento_restringido.py` |

## Qué demuestra

Un servicio onion puede publicarse de modo que **solo sea accesible para clientes que poseen una clave de autorización**. Un cliente sin la clave puede obtener el descriptor desde un HSDir, pero no descifrar su capa interior protegida ni conocer los puntos de introducción necesarios para conectarse. **Descargar el descriptor no equivale a poder descifrarlo**.

El descubrimiento restringido, también llamado autorización de clientes, no es un inicio de sesión de aplicación: actúa antes, durante el propio descubrimiento del servicio. **Condición de seguridad:** Tor solo activa esta autorización si carga al menos un archivo `.auth` válido. Si no se activa ninguna autorización, el servicio puede resultar accesible para cualquiera que conozca su dirección. Un directorio `authorized_clients` vacío **no constituye protección**.

## Preparación

 Ejecuta desde la raíz del repositorio y solo en la **red privada prescindible**. Construye primero la imagen con `make -C labs/es/laboratorio image` cuando sea la primera ejecución; no inicies simultáneamente otras ediciones porque comparten puertos. Comandos previstos:

```bash
make -C labs/es/laboratorio start
python3 -m http.server 8080 --bind 127.0.0.1 &
export PYTHONPATH=labs/es/codigo
```

El script está pensado para poder ejecutarse varias veces **si concluye limpiamente**, y evita sobrescribir directorios de autorización preexistentes. Genera un par X25519 para el cliente, instala el material público de autorización en el nodo de servicio `009h`, prueba el acceso con clave y sin ella y finalmente restaura la configuración inicial. La implementación está en el repositorio; requiere la red privada en marcha.

## Ejecutar el experimento

```bash
make -C labs/es/laboratorio descubrimiento
```

## Salida histórica de referencia (no garantizada)

```text
service ristretto: 4stlyhm3pkptxitznaip66qf3tnuhujabwq6louhibhds7lwk7qcoeyd.onion
without key: 000
with key: 200
```

Estas líneas son la salida literal histórica del laboratorio original, no una ejecución española. La versión localizada imprime `servicio restringido`, `sin clave` y `con clave`; los códigos HTTP `000` y `200` permanecen invariantes.

Interpretación:

- **`000`** significa que curl **no obtuvo un código HTTP**, no que se haya demostrado un rechazo criptográfico por falta de clave. También aparece si falla SOCKS, el servidor local no está activo, hay un timeout o el descriptor no se ha publicado. La salida por sí sola no distingue esas causas.
- **`200`** es la respuesta del servidor HTTP local tras instalar la clave privada; no permite deducir por sí sola la causa del fallo sin clave.
- La dirección del servicio cambia cuando se crea una nueva identidad para este servicio temporal. Los tiempos y códigos mostrados son solo una referencia histórica.

## Funcionamiento resumido

1. Crear un **segundo** servicio onion en el nodo `009h`, bajo `restricted_service`, sin modificar el servicio onion habitual de la red. Generar un par X25519 para el cliente autorizado.
2. Guardar la mitad **pública** bajo `<HiddenServiceDir>/authorized_clients/alice.auth`, con formato `descriptor:x25519:<clave-base32>`.
3. Guardar la mitad **privada** en el cliente, en un archivo `.auth_private` dentro del directorio `ClientOnionAuthDir`, con formato `<dirección>:descriptor:x25519:<clave>`.
4. Recargar el servicio para que publique el descriptor protegido **solo si Tor ha aceptado al menos un archivo `.auth` válido**. El script comprueba el PID y la línea de comandos antes de dirigir HUP al proceso específico.

## Dos problemas que hicieron perder tiempo

**Rutas dentro del contenedor.** `ClientOnionAuthDir` debe contener una ruta válida **dentro del contenedor**, no su equivalente en el anfitrión. Si es incorrecta, tor termina con un error de configuración. El script original deduce la ruta interior adecuada desde `DataDirectory` del nodo.

**Directorio vacío: riesgo de pérdida de protección.** El experimento histórico con tor 0.4.9.13 registró un rechazo `400 Invalid HS descriptor`, pero **no es una garantía de seguridad**. Según las especificaciones y la documentación del Proyecto Tor, la autorización solo se activa al cargarse al menos una entrada `.auth` válida; sin ella, un servicio puede quedar accesible a quien sepa su dirección. Verifica el estado real de la autorización, no solo la presencia del directorio.

Si la red de pruebas queda en ese estado incompleto, inspecciona el directorio:

```bash
ls labs/es/laboratorio/net/nodes/009h/restricted_service/authorized_clients/
```

**No utilices** el antiguo comando `pkill -HUP -f 009h/torrc`: puede abarcar procesos inesperados. El programa actualizado identifica el PID exacto mediante `/lab/net/nodes/<nodo>/pid` y comprueba su línea de comandos antes de enviar HUP. Si la recarga o recuperación falla, detente y revisa manualmente el proceso Tor, las configuraciones y los archivos de claves conservados.

El contenedor de esta edición se llama `torbook-es-network`. Cualquier eliminación de directorios debe hacerse solo dentro del estado prescindible de `labs/es/laboratorio/net/`: nunca apliques estas acciones sin revisarlas a un servicio onion real.

## Protección de claves, limpieza y pruebas offline

El archivo `descubrimiento_restringido.py` **genera claves efímeras X25519**. Crea `authorized_clients/alice.auth` **antes** de recargar el servicio; no se crea deliberadamente un servicio de descubrimiento restringido con la carpeta vacía. Escribe el archivo privado `alice.auth_private` solo en el directorio del cliente y establece permisos restringidos (`0600`) para ambos archivos.

El script guarda ambos contenidos originales de `torrc` y trata de restaurarlos en un bloque `finally`, aun si falla la publicación o HTTP. Si **falla la recarga de Tor tras restaurar los archivos, conserva las claves temporales** y devuelve un error para que puedan inspeccionarse; no elimina los directorios mientras no haya confirmado la recarga. Rechaza una nueva ejecución si existen `restricted_service`, `onion_auth` o un `ClientOnionAuthDir` previo. Una interrupción abrupta (`SIGKILL` o corte de corriente) puede impedir que se ejecute `finally`: revisa el estado antes de repetir el experimento.

Requisitos para ejecutarlo desde el anfitrión: Python, `cryptography`, Docker y el contenedor privado `torbook-es-network` iniciado con la topología `book`. Un servidor HTTP propio debe estar disponible en `127.0.0.1:8080`.

Las pruebas unitarias de generación de formatos y las barreras contra sobrescrituras o destinos externos pueden ejecutarse sin Docker:

```bash
PYTHONPATH=labs/es/laboratorio python3 -m pytest -q labs/es/laboratorio/test_descubrimiento_restringido.py
```

 No sustituye a comprobar el rechazo real de un cliente sin autorización.

## Verificación automática

La comprobación `lab13` del verificador italiano valida los dos resultados impresos (`000` y `200`), pero **no demuestra la causa** de una solicitud sin respuesta ni que todo el descriptor esté correctamente protegido. La versión española comprueba esas dos observaciones y devuelve estado de error cuando fallan; se trata de un criterio didáctico, no de un análisis criptográfico completo.

## Problemas conocidos

| Síntoma | Causa |
|---|---|
| Ambas solicitudes devuelven `000` | Es posible que el servicio no haya publicado de nuevo su descriptor. Deja tiempo para que llegue a los HSDir. |
| El cliente de laboratorio termina | En `ClientOnionAuthDir` se indicó una ruta del anfitrión, no del contenedor. |
| Aparece `400 Invalid HS descriptor` o un acceso sin autorización funciona | Comprobar que Tor realmente cargó un archivo `.auth` válido; no interpretar un directorio vacío como protección. |

Referencia técnica: [Tor Project — Client Authorization](https://community.torproject.org/onion-services/advanced/client-auth/) y [Tor Specifications — Restricted Discovery](https://spec.torproject.org/rend-spec/restricted-discovery.html).
