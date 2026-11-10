# Laboratorio 7 — Selección de rutas ponderada por ancho de banda

| | |
|---|---|
| **Capítulo** | 13 — Selección de rutas |
| **¿Requiere la red?** | La simulación es local; la preparación descarga el consenso histórico |
| **Requisitos previos** | Laboratorio 6 (`directory.py`) |
| **Duración** | Unas dos horas de implementación; un minuto para repetirlo |
| **Módulo** | `labs/es/codigo/torlab/path_selection.py` |

## Qué demuestra

**Alcance:** este es un modelo estadístico simplificado, **no el selector completo de Tor**. Omite familias de repetidores, políticas de salida por destino y puerto, gestión completa de guardias persistentes, restricciones de subred IPv6 y excepciones configurables. `probabilities()` calcula cuotas de peso antes de excluir candidatos; no son probabilidades finales condicionadas a las demás elecciones de una ruta.

Elegir tres repetidores para un circuito Tor no consiste en extraer tres elementos al azar sin más. Cada repetidor se selecciona con probabilidad proporcional a su ancho de banda, ajustado por un peso que depende de su tipo —guardia, salida, ambos o ninguno— y de la posición en el circuito. Además, se aplican restricciones: tres repetidores diferentes, tres redes /16 distintas, un guardia en la primera posición y una salida en la tercera.

Se utiliza un **consenso público**, no la red privada de diez nodos, porque esta última es demasiado pequeña para representar las proporciones de la red.

## Preparación

El repositorio no incluye el consenso público histórico. Desde la raíz ejecuta `make -C labs/es data`; `fetch-public-data.sh` extrae la instantánea del 23 de septiembre de 2026 del archivo mensual de CollecTor a `labs/es/datos/collector/`. Solo se necesita Internet durante la preparación. La antigua URL `/recent/` no es un enlace de archivo permanente.

```bash
make -C labs/es data
export PYTHONPATH=labs/es/codigo
```

La salida siguiente depende de la instantánea exacta.

## Ejecutar el experimento

```bash
export PYTHONPATH=labs/es/codigo
python3 - <<'EOF'
import random
from collections import Counter
from torlab.directory import parse_consensus
from torlab.path_selection import Selector, probabilities, top_share, _relay_type, network16
from torlab.metrics import summary

c = parse_consensus(open(
    "labs/es/datos/collector/consensus-microdesc-2026-09-23-15").read())
r = summary(c)
print(f"repetidores: {r['relay']}")
print(f"ancho de banda con Guard: {100*r['guard_bandwidth_share']:.1f}%    "
      f"ancho de banda con Exit: {100*r['exit_bandwidth_share']:.1f}%")

for pos in ("guard", "middle", "exit"):
    p = probabilities(c, pos)
    print(f"{pos:<6}: elegibles {len(p):>5}; "
          f"primeros 10 = {100*top_share(p, 10):.1f}%; primeros 100 = {100*top_share(p, 100):.1f}%")

sel, rng = Selector(c), random.Random(7)    # semilla fija: resultados reproducibles
g, m, e = sel.path(rng)
# Comprobar la ruta normal, sin guardia preestablecido
assert len({x.id_rsa for x in (g, m, e)}) == 3
assert len({network16(x) for x in (g, m, e)}) == 3
assert "Guard" in g.flag and "Exit" in e.flag and "BadExit" not in e.flag
for name, x in (("guard", g), ("middle", m), ("exit", e)):
    print(f"{name:<6} {x.name:<20} {x.ip:<16} /16 {network16(x):<8} banda {x.bandwidth}")

types = Counter("".join(_relay_type(x) for x in sel.path(rng)) for _ in range(20000))
print("20000 rutas:", "  ".join(f"{k} {100*v/20000:.1f}%" for k, v in types.most_common()))
EOF
```

## Resultado original de referencia

**No utilices este generador para circuitos reales:** `random.Random(7)` produce una secuencia predecible a propósito para repetir la simulación. No sustituye la aleatoriedad criptográficamente adecuada para la selección de rutas de un cliente Tor.

La tabla es una referencia histórica. `random.Random(7)` solo hace reproducibles las extracciones si coinciden también el archivo de consenso y la versión del código. Ni las cantidades de repetidores ni los tiempos son invariantes.

`Selector` excluye candidatos de peso cero; en cambio, `probabilities()` conserva los elegibles de peso cero en su diccionario. El número mostrado como «elegibles» no tiene por qué ser la cantidad de nodos con probabilidad estrictamente positiva.

```text
repetidores: 9358
ancho de banda con Guard: 70.1%    ancho de banda con Exit: 33.1%
guard : elegibles  5306; primeros 10 = 1.7%; primeros 100 = 12.6%
middle: elegibles  8961; primeros 10 = 2.8%; primeros 100 = 13.7%
exit  : elegibles  3126; primeros 10 = 2.3%; primeros 100 = 13.7%
20000 rutas: gge 30.9%  ggd 29.4%  gme 20.4%  gmd 19.3%
```

Las etiquetas se han adaptado a los `print` españoles. La fila de una ruta concreta se omite porque cambia con el consenso; importan la diversidad de identidades RSA y de subredes /16 en el ejemplo sin guardia fijado.

Interpretación:

- Las abreviaturas finales indican tipos de repetidor: `g` es guardia, `e` solo salida, `d` guardia y salida simultáneamente y `m` ninguno. `gge` significa guardia en primer lugar, otro repetidor con indicador Guard en el medio y un repetidor solo de salida al final.
- Ninguna ruta de esta instantánea utiliza repetidores de salida en la primera o segunda posición porque los pesos correspondientes del consenso son cero. La capacidad de salida se considera escasa y se reserva para cuando hace falta.
- Muchas rutas incluyen otro repetidor con indicador Guard como intermedio: los guardias aportan gran parte del ancho de banda y no es necesario excluirlos de ese papel.
- La concentración es moderada: las diez salidas con más probabilidad representan una fracción relativamente pequeña del total. Si unos pocos repetidores dominaran la red, sería más fácil atacarla.

**La semilla importa.** La última línea es una muestra. `random.Random(7)` permite reproducirla; modificar la semilla cambia ligeramente los porcentajes. Sin una semilla fija, comparar ejecuciones generaría ruido innecesario.

## Pruebas unitarias sin datos públicos

Las pruebas de `test_path_selection.py` utilizan el consenso firmado de la **red privada** incorporado en el laboratorio 6; no necesitan descargar la instantánea pública de CollecTor. Comprueban rutas con tres repetidores distintos, rechazo de una red /16 común y ponderación de salidas que también tienen el indicador `Guard`.

Comando previsto desde la raíz del repositorio:

```bash
PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test/test_directory.py labs/es/codigo/torlab/test/test_path_selection.py
```

 La simulación completa que cita los valores de 9358 repetidores **sí necesita** la instantánea pública exacta especificada en *Preparación*; no se puede reproducir legítimamente con los ocho repetidores de la red privada.

## Verificación automática

El verificador italiano `lab7` usa 500 rutas de un consenso público guardado. Las pruebas unitarias locales `labs/es/codigo/torlab/test/test_path_selection.py` utilizan el consenso privado de ocho nodos y desactivan `distinct_networks` al construir rutas, porque todos usan una misma /16. No acreditan la diversidad /16 de la red pública.

Para el ejemplo sin guardia fijo, comprueba las identidades RSA y las subredes IPv4 /16, nunca solamente los sobrenombres.

La comprobación original `lab7` genera 500 rutas y verifica cuatro invariantes: tres identidades distintas, tres redes /16 distintas, guardia inicial y salida final.

Un detalle ya provocó un error en el verificador original: **los sobrenombres no son únicos** en la red pública. En la instantánea estudiada, 151 sobrenombres estaban compartidos. Compara repetidores por identidad y no por nombre.

## Problemas conocidos

- `FileNotFoundError` para el consenso: revisa el apartado *Preparación*.
- Construir 20 000 rutas llevó unos siete segundos en el entorno original. Si tarda cientos de segundos, puede que estés recalculando pesos de miles de repetidores en cada extracción.

## Continuación

- El [laboratorio 15 — Estadísticas del consenso](Laboratorio-15-Metricas.md) utiliza la misma instantánea.
- El [laboratorio 19 — Tiempo hasta el primer compromiso](Laboratorio-19-Simulacion.md) reutiliza este selector para simular seis meses de comportamiento.

---

# Implementación detallada

`labs/es/codigo/torlab/path_selection.py` traslada al código dos partes de las especificaciones: las restricciones de selección de `path-spec` y los pesos de `dir-spec`.

## Tipo de repetidor

```python
def _relay_type(r: RelayEntry) -> str:
    """g = solo Guard; e = solo Exit; d = ambos; m = ninguno."""
    g, e = "Guard" in r.flag, "Exit" in r.flag and "BadExit" not in r.flag
    return {(True, True): "d", (True, False): "g", (False, True): "e", (False, False): "m"}[(g, e)]
```

`BadExit` forma parte de la **definición de salida utilizable**. Un repetidor puede tener indicador `Exit`, pero las autoridades pueden marcarlo `BadExit`; entonces debe excluirse de la selección de salidas. Olvidarlo enviaría tráfico a repetidores declarados inadecuados.

Las letras son la clasificación interna del módulo: `d` para guardia y salida, `g` solo guardia, `e` solo salida y `m` intermedio o ninguno de los anteriores.

## Calcular los pesos

```python
def weight(r: RelayEntry, position: str, weights: dict[str, int], scale: int = 10000) -> float:
    """Aplica W<posición><tipo> dividido entre bwweightscale del consenso."""
    _check_position(position)
    _check_scale(scale)
    bw = r.bandwidth if r.bandwidth is not None else 0
    if isinstance(bw, bool) or not isinstance(bw, int) or bw < 0:
        raise ValueError("ancho de banda del repetidor no válido")
    factor = weights.get(f"W{position[0]}{_relay_type(r)}", scale)
    if isinstance(factor, bool) or not isinstance(factor, int) or not 0 <= factor <= scale:
        raise ValueError("peso de ancho de banda del consenso no válido")
    return bw * factor / scale
```

La clave de peso se **construye**, no se elige mediante una larga cadena de `if`: la primera letra representa la posición del circuito y la segunda el tipo del repetidor. Así, `Wmg` significa el peso aplicado a un repetidor con capacidad de guardia cuando se selecciona como intermedio.

Detalles:

- Si falta un valor de ancho de banda, el peso es cero; un ancho de banda negativo o no entero es un error del consenso.
- El valor predeterminado `scale` significa peso completo cuando falta esa clave concreta.
- Dividir entre `scale` convierte los pesos enteros del consenso en un factor entre 0 y 1. La escala es el parámetro del consenso `bwweightscale` (por defecto 10000), que `Selector` lee de los parámetros del consenso.

En la instantánea de septiembre de 2026, los pesos relevantes de guardia e intermedio para repetidores con capacidad de salida son cero; así no se consume ancho de banda de salida donde no se necesita.

## Por qué los pesos se calculan una sola vez

`Selector` excluye candidatos de peso cero; en cambio, `probabilities()` conserva los elegibles de peso cero en su diccionario. El número mostrado como «elegibles» no tiene por qué ser la cantidad de nodos con probabilidad estrictamente positiva.

```python
class Selector:
    """Almacena los repetidores aptos y los pesos por posición.

    Seleccionar entre candidatos válidos evita rechazos por pesos muy pequeños.
    """

    def __init__(self, consensus: Consensus):
        self.scale = consensus.parameters.get("bwweightscale", 10000)
        _check_scale(self.scale)
        self.candidates, self.weights = {}, {}
        for pos in POSITIONS:
            candidates = [r for r in consensus.relay if eligible(r, pos)]
            values = [weight(r, pos, consensus.weights, self.scale) for r in candidates]
            self.candidates[pos] = [r for r, w in zip(candidates, values) if w > 0]
            self.weights[pos] = [w for w in values if w > 0]
```

Una versión inicial filtraba más de nueve mil repetidores y recalculaba sus pesos **en cada extracción**. Tardaba unos 310 segundos para 2000 rutas. Preparar de antemano candidatos y pesos redujo drásticamente el trabajo y permitió simulaciones repetidas.

Los repetidores con peso efectivo cero se eliminan inmediatamente. Conservarlos solo generaría selecciones inútiles que habría que descartar.

## Restricciones mediante muestreo con rechazo

La comprobación `/16` educativa cubre IPv4 solamente. Tor utiliza reglas de subred configurables, también para IPv6 (habitualmente `/32`), y prevé excepciones para determinados circuitos onion.

```python
    def choose(self, pos: str, excluded: list[RelayEntry], rng: random.Random,
               distinct_networks: bool = True, attempts: int = 1000) -> RelayEntry:
        """Elige candidatos viables; se conserva attempts por compatibilidad."""
        _check_position(pos)
        if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts <= 0:
            raise ValueError("el número de intentos debe ser positivo")
        excluded_ids = {r.id_rsa for r in excluded}
        excluded_nets = {network16(r) for r in excluded} if distinct_networks else set()
        pairs = [(r, w) for r, w in zip(self.candidates[pos], self.weights[pos])
                 if r.id_rsa not in excluded_ids
                 and (not distinct_networks or network16(r) not in excluded_nets)]
        if not pairs:
            raise LookupError(f"no hay repetidores aptos para la posición {pos}")
        return rng.choices([r for r, _ in pairs], weights=[w for _, w in pairs])[0]
```

Se cumplen las restricciones **extrayendo candidatos y rechazando los inadecuados**, en vez de reconstruir toda la lista antes de cada elección. En una red amplia, los rechazos son raros y este método resulta más eficiente que filtrar miles de entradas repetidamente.

Los intentos se limitan a 1000 porque, en una red diminuta, el rechazo podría prolongarse mucho: si casi todos los candidatos están en la misma /16, las extracciones válidas son raras. Agotados los intentos, `choose` filtra los repetidores compatibles y elige entre ellos; si no queda ninguno, lanza una excepción clara en lugar de bloquearse.

Dos repetidores cuentan como el mismo cuando tienen la misma identidad RSA, no cuando son el mismo objeto Python.

> **Los sobrenombres no son únicos.** En la instantánea pública, 151 estaban compartidos. Comparar los nombres en lugar de las identidades del repetidor puede invalidar silenciosamente las restricciones.

## Orden de selección

```python
    def path(self, rng: random.Random, guard: RelayEntry | None = None,
             distinct_networks: bool = True) -> tuple[RelayEntry, RelayEntry, RelayEntry]:
        """Primero Exit, luego un Guard validado y, finalmente, el nodo intermedio."""
        if guard is not None:
            guard = next((r for r in self.candidates["guard"]
                          if r.id_rsa == guard.id_rsa), None)
            if guard is None:
                raise LookupError("el Guard fijado no pertenece a los candidatos aptos")
        e = self.choose("exit", [guard] if guard is not None else [], rng, distinct_networks)
        g = guard if guard is not None else self.choose("guard", [e], rng, distinct_networks)
        m = self.choose("middle", [e, g], rng, distinct_networks)
        return g, m, e
```

El código elige **primero la salida**, después el guardia y por último el intermedio. No es casual: la salida suele ser la posición más restringida, pues debe admitir el destino. Elegirla al final aumentaría la probabilidad de que las primeras elecciones no dejaran una salida compatible y obligaran a comenzar de nuevo.

El argumento opcional `guard` permite fijar el primer salto. El [laboratorio 19](Laboratorio-19-Simulacion.md) lo utiliza para modelar guardias persistentes. Un guardia fijado se busca primero entre los candidatos aptos del consenso (`LookupError` si no está) y después se elige la salida excluyéndolo por identidad y por red /16, de modo que las restricciones también se cumplen en este caso.

## Límites deliberados del modelo

**Alcance:** este es un modelo estadístico simplificado, **no el selector completo de Tor**. Omite familias de repetidores, políticas de salida por destino y puerto, gestión completa de guardias persistentes, restricciones de subred IPv6 y excepciones configurables. `probabilities()` calcula cuotas de peso antes de excluir candidatos; no son probabilidades finales condicionadas a las demás elecciones de una ruta.

El módulo implementa las restricciones principales, no todo el algoritmo de producción. Omite deliberadamente:

- **Familias de repetidores**, que requieren microdescriptores y quedan como ejercicio.
- Muestras persistentes de guardias filtrados, confirmados y primarios.
- Vanguards de servicios onion.
- Aislamiento de flujos y preferencias de puertos.

Incluir todos los detalles de producción sería más realista, pero dificultaría entender la causa de cada efecto. El código didáctico mantiene visibles las relaciones entre reglas y resultados.

## Procedencia de las reglas

| En el código | En la especificación |
|---|---|
| Restricciones de ruta | path-spec, *Path selection and constraints* |
| Pesos posicionales | path-spec, *Weighting node selection* |
| Valores `W**` | dir-spec, *Computing Bandwidth Weights* |
| Indicadores de repetidor | dir-spec, *Assigning flags in a vote* |

