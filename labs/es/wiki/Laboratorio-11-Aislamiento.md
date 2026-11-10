# Laboratorio 11 — Aislamiento de flujos en directo

| | |
|---|---|
| **Capítulo** | 18 — Puerto de control y Stem |
| **¿Requiere la red?** | Sí |
| **Requisitos previos** | Red de laboratorio en funcionamiento; `stem` (incluido en el contenedor de referencia) |
| **Duración** | Aproximadamente 1 hora |
| **Archivo incorporado (sin ejecutar)** | `labs/es/laboratorio/aislamiento.py` |

## Qué demuestra

tor no coloca todo el tráfico de las aplicaciones en un mismo circuito. Aísla los flujos según las **credenciales SOCKS** utilizadas. Tor Browser utiliza el mecanismo para aislar los contextos de sitios de primera parte: con `IsolateSOCKSAuth` activo (opción normalmente predeterminada), los flujos con credenciales SOCKS distintas **no pueden compartir un circuito**. Esto no garantiza un circuito por pestaña ni direcciones IP de salida distintas.

El laboratorio también revela un detalle: con Conflux activo, un flujo puede utilizar un **túnel Conflux** formado por dos ramas de circuitos vinculadas. Para interpretar el aislamiento hay que comparar el túnel lógico y no una sola rama.

## Preparación

 Se prevé iniciar la red privada y un servidor HTTP exclusivamente local:

```bash
# En el primer uso: make -C labs/es/laboratorio image
make -C labs/es/laboratorio start
# Servidor web en el puerto 8080, destino utilizado en las pruebas
python3 -m http.server 8080 --bind 127.0.0.1 &
```

El script se ejecuta **dentro del contenedor** de la edición española para utilizar `stem` y el ControlPort del cliente 008c. Puede invocarse mediante Make:

```bash
make -C labs/es/laboratorio aislamiento
```

**El script español ya existe**, y el árbol local se monta en `/lab`. El contenedor utiliza la red del anfitrión (`--network host`), por lo que puede llegar al servidor que escucha en `127.0.0.1:8080`. El script obliga a curl a usar SOCKS para esa dirección con `--noproxy ""`, incluso si el entorno define `NO_PROXY`.

## Resultado de referencia

```text
credentials site-a.example  -> conflux 90EFE5BD       ['test004r', 'test005r', 'test007e']
credentials site-a.example  -> conflux 90EFE5BD       ['test004r', 'test005r', 'test007e']
credentials site-b.example  -> conflux A608C1C1       ['test004r', 'test006e', 'test007e']
credentials -               -> conflux 2FED7F85       ['test004r', 'test003r', 'test007e']
(NEWNYM delayed by 6 s)
after NEWNYM, site-a.example  -> conflux BA715C26
```

Se conserva la salida inglesa original para representar los mensajes y valores observados, no como una ejecución traducida.

Interpretación:

- Las dos primeras solicitudes utilizan las **mismas** credenciales y, en esta captura histórica, reciben el **mismo** túnel. Tor **permite** reutilizar un túnel compatible, pero no garantiza esa reutilización.
- Con `IsolateSOCKSAuth`, las solicitudes con credenciales distintas **no deben compartir circuito**. Los identificadores observados aquí son distintos, sin que eso implique IP de salida distintos.
- Después de `NEWNYM`, las **nuevas solicitudes** deben utilizar circuitos limpios con respecto a los anteriores. La señal **no equivale** a «Nueva identidad» de Tor Browser, que además cierra pestañas y ventanas y borra cookies y otros datos.
- `conflux XXXXXXXX` muestra solo los primeros ocho caracteres de `CONFLUX_ID`; la lista de repetidores corresponde a una rama. Si Conflux no está disponible, puede aparecer `circuito N`.

## Tres dificultades descubiertas durante el experimento

El laboratorio original fallaba intermitentemente por tres motivos:

1. **tor abre flujos por sí mismo.** La actividad del directorio también genera eventos `STREAM`. Contar todos los eventos producía resultados incorrectos. El script filtra por destino y utiliza el evento final correspondiente.
2. **`NEWNYM` puede tener un límite de frecuencia.** En la versión Tor del experimento original, `MAX_SIGNEWNYM_RATE` establecía diez segundos; la especificación permite aplicar límites sin garantizar ese intervalo en todas las versiones. En la ejecución observada se **aplazó** una señal prematura, que podía afectar la siguiente solicitud. El script busca el aviso y espera, pero la ausencia de un aviso no prueba por sí sola que la señal ya se haya aplicado.
3. **Conflux.** Los circuitos están vinculados mediante `CONFLUX_LINKED`. El aislamiento opera sobre el túnel lógico; mirar únicamente las ramas individuales puede hacer parecer que falla.

Queda cierta variabilidad en una red tan pequeña, porque tor dispone de muy pocas combinaciones de repetidores. La comprobación automatizada original admite hasta tres intentos antes de considerar que un fallo de selección de ruta es significativo.

## Verificación automática

La comprobación `lab11` del verificador italiano `scripts/verify_labs.py` evalúa tres observaciones: reutilización del túnel en esa prueba, separación de credenciales diferentes y cambio tras `NEWNYM`. **Tor no garantiza** que dos solicitudes con las mismas credenciales utilicen siempre el mismo túnel. El script español sí comprueba estas condiciones como criterios *didácticos de la prueba* y devuelve un código distinto de cero si alguna falla; esto no convierte todos esos criterios en invariantes del protocolo. `make -C labs/es/laboratorio verify` ejecuta Chutney, no el verificador de aislamiento.

## Problemas conocidos

| Síntoma | Causa |
|---|---|
| El script no encuentra flujos | Falta el servidor en el puerto 8080 o el destino del script no coincide. |
| Credenciales diferentes parecen compartir túnel | Antes de atribuirlo a la selección de rutas, verifica `IsolateSOCKSAuth`, la utilización efectiva de SOCKS y que los eventos pertenecen a las solicitudes observadas. |
| `SocketError` en ControlPort | El cliente 008c no está activo, el puerto 8008 no está accesible o el script se ejecuta fuera del contenedor previsto. |

## Pruebas offline y límites de la verificación

El archivo `labs/es/laboratorio/test_aislamiento.py` prueba sin iniciar Stem, Docker ni Tor el filtrado de eventos `STREAM`, la identificación de las dos ramas de un túnel por `CONFLUX_ID`, la detección de aplazamientos `NEWNYM` y las invariantes de aislamiento positivas y negativas.

```bash
PYTHONPATH=labs/es/laboratorio python3 -m pytest -q labs/es/laboratorio/test_aislamiento.py
```

La batería offline comprueba la lógica de interpretación del script, **no demuestra** que el cliente Tor de la red privada aísle realmente los flujos. Para comprobarlo es necesario ejecutar `make -C labs/es/laboratorio aislamiento` con Chutney activo y el servidor HTTP local escuchando.

La salida histórica anterior conserva sus identificadores de túnel y sus textos en inglés. El nuevo programa español usa las etiquetas `credenciales`, `conflux` o `circuito` y `después de NEWNYM`, sin alterar las credenciales SOCKS ni los parámetros del protocolo.

