# Laboratorio 19 — Tiempo hasta el primer compromiso

| | |
|---|---|
| **Capítulo** | 29 — Investigación académica sobre Tor |
| **¿Requiere la red?** | No necesita ejecutar Tor; la primera descarga del consenso histórico sí requiere HTTPS |
| **Requisitos previos** | Laboratorios 7 y 15 |
| **Duración** | Entre 1 y 2 horas para implementarlo; tiempo de ejecución según la máquina |
| **Módulo** | `labs/es/codigo/torlab/simulation.py` |

## Qué demuestra

Este laboratorio aísla el efecto de los guardias persistentes. En la simulación de referencia, un adversario que controla el 5 % del ancho de banda ponderado de guardias y el 5 % del de salidas compromete a **la mitad de los clientes en quince días** si se elige un guardia nuevo para cada circuito, y a casi todos en tres meses. Con guardias persistentes, el 18,4 % queda comprometido después de seis meses.

Los guardias persistentes no reducen la probabilidad media de compromiso por circuito en un modelo sencillo: **concentran** la exposición. La mayoría de los clientes conserva un guardia honesto y tiene poca exposición en la entrada durante el período simulado; los que escogieron un guardia malicioso permanecen expuestos.

## Preparación

Como en el [laboratorio 7](Laboratorio-07-Rutas.md), la reproducción de las cifras históricas requiere el consenso `labs/es/datos/collector/consensus-microdesc-2026-09-23-15`. El módulo tiene su prueba unitaria; la instantánea pública exacta se descarga con `make -C labs/es data`. Para obtener el archivo público, ejecuta `make -C labs/es data` desde la raíz del repositorio (descarga HTTPS de CollecTor). Las pruebas offline usan otro consenso, el de la red privada preservada en `labs/es/codigo/torlab/test/data/`, por lo que no reproducen las mismas cifras.

## Ejecutar el experimento

Comandos de la edición española (requieren añadir antes el consenso público histórico):

```bash
export PYTHONPATH=labs/es/codigo
python3 -m torlab.simulation labs/es/datos/collector/consensus-microdesc-2026-09-23-15 0.05
```

El segundo argumento es la cuota de ancho de banda del adversario: aquí, 5 %.

## Resultado de referencia

```text
adversario: 5% del ancho de banda de guardias y 5% de salidas; 2000 clientes, 180 días, 20 circuitos/día
guardia persistente    1d:  2.6%    7d:  4.4%   30d:  4.4%   90d:  9.4%  180d: 18.4%  mediana: None
guardia por circuito   1d:  4.3%    7d: 27.9%   30d: 76.5%   90d: 98.9%  180d: 100.0%  mediana: 15
```

La simulación original es **determinista**, porque fija la semilla aleatoria. Dos ejecuciones contra el mismo consenso producen los mismos resultados. Si las cifras cambian, comprueba primero el archivo del consenso. La salida está adaptada al texto que imprime el módulo español; los valores son históricos y no representan una nueva ejecución. La versión localizada traduce las etiquetas `adversario`, `guardia persistente`, `guardia por circuito` y `mediana`; la simulación, sus parámetros y la semilla siguen siendo los mismos.

Interpretación:

- **Guardia persistente:** el compromiso aumenta pronto entre quienes eligieron inicialmente el guardia malicioso, después permanece casi estable hasta la rotación. Las oportunidades nuevas aparecen en cada intervalo de rotación. La simulación reemplaza su único guardia tras un intervalo aproximado de **48–60 días**, inspirado en un guardia **confirmado**. **No reproduce el algoritmo completo de selección de Tor**, que mantiene conjuntos de guardias muestreados y confirmados, gestiona su disponibilidad y permite alternativas. `GUARD_CONFIRMED_MIN_LIFETIME` es por defecto 60 días y `GUARD_LIFETIME` 120 días para guardias no confirmados; los parámetros de red pueden modificar esos valores.
- **Guardia nuevo por circuito:** cada circuito ofrece otra posibilidad de elegir simultáneamente guardia y salida adversarios. La mediana del tiempo hasta el primer compromiso es de quince días en la ejecución de referencia.
- `mediana: None` con guardia persistente significa que menos de la mitad de los clientes simulados quedó comprometida en 180 días; la mediana cae fuera del intervalo observado.

La fuente también registra:

| Cuota del adversario | Comprometidos tras 180 días con guardias persistentes | Sin guardias persistentes |
|---:|---:|---:|
| 1 % | 3,9 % | 30,9 % |
| 5 % | 18,4 % | 100,0 % |

## Modelo y limitaciones

El modelo tiene 2000 clientes, 180 días y 20 circuitos por cliente y día. Un cliente se considera comprometido el primer día en que un circuito contiene **tanto** el guardia adversario como la salida adversaria.

Deliberadamente omite los intermedios, familias, restricciones /16, guardias alternativos, fallos de conexión, encaminamiento a nivel de sistemas autónomos y muchos detalles de producción. Sirve para aislar un mecanismo, **no** para pronosticar tasas reales de desanonimización.

Para mejorar el rendimiento, selecciona repetidores mediante búsqueda binaria entre pesos acumulados, en vez de llamar repetidamente a `random.choices` sobre miles de repetidores.

## Pruebas offline reproducibles

El archivo `test_simulation.py` utiliza el consenso privado firmado del laboratorio 6: verifica la cuota de una urna ponderada, el caso sin adversario y el efecto de los guardias persistentes en una simulación pequeña.

```bash
PYTHONPATH=labs/es/codigo python3 -m pytest -q labs/es/codigo/torlab/test/test_simulation.py
```

Este conjunto de tests no necesita iniciar Tor o Chutney. Los resultados numéricos de una simulación con el consenso privado **no sustituyen** los del consenso público fechado. La semilla permanece fija, pero el método es una simplificación educativa y no estima la desanonimización real de usuarios.

## Verificación automática

La comprobación `lab19` del verificador italiano se ejecuta sobre el módulo italiano, **no sobre la traducción española**, y fija dos resultados del consenso público original: 18,4 % de compromiso tras seis meses con guardias persistentes y 100 % con mediana de quince días con guardia nuevo por circuito. El test español comprueba el muestreo, el control sin adversario y que los guardias persistentes reducen la exposición en un experimento corto. Los números históricos exactos siguen sin verificarse en español.

## Problemas conocidos

La simulación usa únicamente la biblioteca estándar y los módulos locales de `torlab`, pero para las cifras históricas exige el consenso archivado exacto y una descarga HTTPS inicial. Los resultados de la red privada pueden diferir.

## Cómo continuar

- El capítulo 13 explica la duración del guardia confirmado y la diferencia entre `GUARD_LIFETIME` y `GUARD_CONFIRMED_MIN_LIFETIME`.
- El capítulo 26 examina la correlación de tráfico modelada aquí, mientras el [laboratorio 16](Laboratorio-16-Correlacion.md) la demuestra utilizando exclusivamente tráfico generado por el experimento.
