# Laboratorio 20 — Arti en la red privada

| | |
|---|---|
| **Capítulo** | 30 — Arti, la implementación en Rust |
| **¿Requiere la red?** | Sí; también Rust para compilar Arti |
| **Requisitos previos** | Red privada en funcionamiento; `cargo` |
| **Duración** | Alrededor de 1 hora, más el tiempo de compilación |
| **Generador de configuración** | `labs/es/laboratorio/arti_config.py` — 7 pruebas offline PASS en Windows |

## Qué demuestra

La red privada del libro no es «una red para la implementación de tor en C»: es una red del **protocolo Tor**. Una implementación independiente puede incorporarse, descargar información de directorio, construir circuitos y transmitir tráfico mediante repetidores programados en C, sin que estos necesiten saber cuál es la implementación del cliente.

Esto constituye una evidencia sólida de que los formatos estudiados a lo largo del libro son formatos interoperables del protocolo, no convenciones particulares de una implementación.

## Preparación

Compila la versión histórica Arti 2.6.0 **solo para reproducir este experimento en una red privada controlada**; no se recomienda desplegar esa versión antigua en la red Tor pública. Versiones posteriores, incluida Arti 2.7.0 (octubre de 2026), incorporan correcciones de seguridad. Las rutas siguientes corresponden a la edición española:

```bash
mkdir -p labs/es/vendor
git clone https://gitlab.torproject.org/tpo/core/arti.git labs/es/vendor/arti
git -C labs/es/vendor/arti checkout arti-v2.6.0
(cd labs/es/vendor/arti && cargo build --release -p arti --locked)
```

Genera después una configuración para la red privada:

```bash
export PYTHONPATH=labs/es/codigo
make -C labs/es/laboratorio arti-config
```

El script lee identidades y puertos de las tres autoridades desde los archivos de los nodos y escribe `labs/es/laboratorio/net/arti/arti.toml`. Adaptará las opciones del entorno de prueba: autoridades privadas y fallbacks, direcciones locales, ausencia de restricciones de diversidad por subred —todos los nodos están en loopback— e intervalo HSDir reducido.

## Ejecutar el experimento

Desde la raíz del repositorio, ejecuta lo siguiente en una shell POSIX, con la red privada ya iniciada mediante `make -C labs/es/laboratorio start` (no la inicies otra vez si ya está activa). El control verifica **tanto** el estado HTTP **como** el contenido fijo de la respuesta, para no confundir otro servicio en el puerto 8080 con el servidor de laboratorio. Este servidor no expone los archivos del directorio actual.

```sh
(
set -eu
ARTI_BIN="labs/es/vendor/arti/target/release/arti"
ARTI_CFG="labs/es/laboratorio/net/arti/arti.toml"
ARTI_LOG="labs/es/laboratorio/net/arti/arti.log"
HTTP_LOG="labs/es/laboratorio/net/arti/http.log"
ARTI_PID=
HTTP_PID=
BODY_FILE=

cleanup() {
  if [ -n "$HTTP_PID" ]; then
    kill "$HTTP_PID" 2>/dev/null || true
    wait "$HTTP_PID" 2>/dev/null || true
  fi
  if [ -n "$ARTI_PID" ]; then
    kill "$ARTI_PID" 2>/dev/null || true
    wait "$ARTI_PID" 2>/dev/null || true
  fi
  if [ -n "$BODY_FILE" ]; then rm -f "$BODY_FILE"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

[ -x "$ARTI_BIN" ] && [ -f "$ARTI_CFG" ] || {
  echo "Falta el ejecutable de Arti o la configuración privada" >&2
  exit 1
}
: > "$ARTI_LOG"
"$ARTI_BIN" proxy -c "$ARTI_CFG" > "$ARTI_LOG" 2>&1 &
ARTI_PID=$!

# Esperar al arranque de esta instancia de Arti
ready=0
n=0
while [ "$n" -lt 60 ]; do
  if grep -q "proxy now functional" "$ARTI_LOG" && kill -0 "$ARTI_PID" 2>/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$ARTI_PID" 2>/dev/null; then
    echo "Arti terminó antes de completar el arranque; consulta $ARTI_LOG" >&2
    exit 1
  fi
  n=$((n + 1))
  sleep 2
done
[ "$ready" -eq 1 ] || {
  echo "Arti no completó el arranque; consulta $ARTI_LOG" >&2
  exit 1
}

# Servidor HTTP local: respuesta fija únicamente para /
python3 -u - > "$HTTP_LOG" 2>&1 <<'PY' &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        body = b"arti-private-lab-ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass

ThreadingHTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
PY
HTTP_PID=$!
sleep 1
kill -0 "$HTTP_PID" 2>/dev/null || {
  echo "El servidor HTTP local no arrancó; consulta $HTTP_LOG" >&2
  exit 1
}

BODY_FILE=$(mktemp)
HTTP_CODE=$(curl --fail --silent --show-error --max-time 30 \
  --noproxy "" --socks5-hostname 127.0.0.1:9150 \
  -o "$BODY_FILE" -w '%{http_code}' http://127.0.0.1:8080/)
[ "$HTTP_CODE" = "200" ] && [ "$(cat "$BODY_FILE")" = "arti-private-lab-ok" ] || {
  echo "Respuesta HTTP inesperada del laboratorio privado" >&2
  exit 1
}
printf '%s\n' "$HTTP_CODE"
)
```

El ejemplo vacía el registro antiguo, comprueba que **esta instancia de Arti** sigue viva, falla si otro proceso ocupa el puerto 8080 y termina **solo sus propios procesos** incluso en errores e interrupciones controladas. No utiliza `pkill` sobre procesos ajenos. Se acepta el código `200` **solo si** la respuesta contiene exactamente `arti-private-lab-ok` y curl termina correctamente. La prueba necesita conectividad del servidor local a través de las salidas de la **red privada**, no supone que la red Tor pública permita acceso a loopback.

La expresión `proxy now functional` es una cadena literal del registro de Arti: no debe traducirse en el comando `grep`. La salida `200` que se muestra después solo aparece cuando coinciden estado y cuerpo de respuesta.

## Salida histórica de referencia

```text
2026-09-24T16:05:45Z  INFO arti::subcommands::proxy: Sufficiently bootstrapped; proxy now functional.
200
```

Interpretación:

- Arti descargó y verificó la información de directorio de las autoridades privadas, completó el arranque, construyó un circuito y entregó satisfactoriamente una solicitud HTTP por la misma red de repetidores. Estos no necesitan distinguir qué implementación de cliente se comunica con ellos.
- El argumento vacío `--noproxy ""` evita que `NO_PROXY`/`no_proxy` desvíe el tráfico HTTP local fuera de SOCKS. Los registros y el resultado HTTP son históricos, no una nueva ejecución.
- En este entorno, el puerto SOCKS de Arti es **9150**, como se utiliza habitualmente en Tor Browser, y no el puerto 9050 predeterminado del programa tor independiente.

## Diferencias respecto a tor

Arti se configura con TOML y no con `torrc`. Las entradas de autoridades privadas incluyen campos como `rsa_identity`, `ed_identity` y `orports`, con ambas identidades, RSA histórica y Ed25519.

El capítulo 30 explica las funciones admitidas por Arti y las funciones que faltan deliberadamente, incluida la operación de repetidores como ámbito de implementación distinto.

Debe conservarse una corrección importante descubierta en la fuente: una tabla de versiones de `Compatibility.md` de Arti estaba desplazada en una unidad para `FlowCtrl` respecto a torspec. La especificación y el consenso público observado (`FlowCtrl=1-2`) indican que 1 corresponde a `AUTH_SENDME` y 2 al control de congestión. Si la documentación de una implementación contradice la especificación, ambas y los datos reales deben comprobarse directamente.

## Pruebas offline del generador TOML

El generador localizado lee solamente los archivos privados de `labs/es/laboratorio/net/nodes/` y guarda `arti.toml` en `labs/es/laboratorio/net/arti/`. Ese directorio es material de laboratorio **excluido de Git**, y la configuración se debe regenerar si Chutney crea nuevas identidades. El script no descarga fuentes externas y no inicia Arti.

Se han incorporado tests que construyen tres autoridades sintéticas en una carpeta temporal, analizan el TOML con `tomllib` y comprueban los puertos, las identidades, el intervalo HSDir y las reglas especiales para la topología `127.0.0.1`:

```bash
PYTHONPATH=labs/es/laboratorio python3 -m pytest -q labs/es/laboratorio/test_arti_config.py
```

Se requiere Python 3.11 o superior para usar `tomllib`. Estas **siete pruebas offline se ejecutaron correctamente en Windows (14 de octubre de 2026)**. Confirman la generación de TOML para rutas Windows y los parámetros comprobados; **no certifican** que Arti arranque, complete el bootstrap o entregue peticiones HTTP.

## Verificación automática

La comprobación de referencia `scripts/verify_labs.py::lab20` **utiliza la estructura italiana de la raíz** (`fonti/arti/target/release/arti` y `laboratorio/arti_config.py`), no los archivos `labs/es/...`; por tanto no certifica automáticamente la edición española. Si falta su binario, la prueba se **omite, no se aprueba**. El generador y sus pruebas offline españolas solo evalúan el TOML.

## Problemas conocidos

| Síntoma | Causa |
|---|---|
| `Lab 20: Arti binary not found; laboratory skipped` | Falta `labs/es/vendor/arti/target/release/arti` cuando se use el entorno español. |
| El arranque no termina | La red privada podría estar detenida o `arti.toml` se generó antes de volver a crear la red. Ejecuta `arti_config.py` de nuevo. |
| `Permission denied` en directorios de estado | Arti exige permisos restrictivos. Elimina únicamente el estado de pruebas prescindible bajo `labs/es/laboratorio/net/arti/state` y vuelve a intentarlo. |
| `pkill -f "arti proxy"` o `pkill -x arti` termina procesos ajenos | Evita detener procesos por nombre: los comandos de arriba conservan sus propios PID y los limpian con `trap`. |

