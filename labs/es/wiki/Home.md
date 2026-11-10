# Wiki de los laboratorios

Esta wiki acompaña a *Anatomía de Tor — El protocolo del anonimato, byte a byte*. Documenta los **veinte laboratorios** del libro: qué demuestra cada uno, qué se necesita, los comandos, los resultados esperados y los problemas encontrados en la práctica. Los fragmentos de código de estas páginas están simplificados para la lectura y omiten parte de las comprobaciones de validez: la referencia es el código de `labs/es/codigo` y `labs/es/laboratorio`.

El libro explica *por qué*. Esta wiki ayuda a entender *cómo se realiza* cada experimento.

> Los experimentos de red utilizan una topología Tor privada, sin atacar ni medir a usuarios de la red pública. El laboratorio 2 se realiza sin red; los laboratorios 7, 15 y 19 analizan documentos históricos públicos del Tor Project y pueden requerir obtener el consenso archivado correspondiente.

## Por dónde empezar

1. [Instalación](Instalacion.md): requisitos y preparación desde cero.
2. [La red de laboratorio](Red-de-laboratorio.md): topología, puertos, comandos y recuperación de una red que no responde.
3. [Verificación automática](Verificacion-automatica.md): pruebas Python, verificaciones Chutney y scripts específicos, con requisitos diferentes.
4. [Resolución de problemas](Resolucion-de-problemas.md): errores habituales y sus causas.

## Los veinte laboratorios

Las veinte guías están traducidas y enlazadas. El código y las pruebas offline correspondientes también están en el repositorio. Los laboratorios 7, 15 y 19 necesitan, además, la instantánea pública histórica para reproducir los valores numéricos.

| Laboratorio | Capítulo | Título | ¿Requiere la red? |
|---:|---:|---|:---:|
| 1 | 7 | [Abrir un canal verificado](Laboratorio-01-Canal.md) | Sí |
| 2 | 8 | [Codificar y descodificar celdas](Laboratorio-02-Celdas.md) | No |
| 3 | 9 | [Intercambio de circuito: ntor y ntor-v3](Laboratorio-03-Handshake.md) | Sí |
| 4 | 10 | [Cifrado por capas y un circuito de tres saltos](Laboratorio-04-Cifrado.md) | Sí |
| 5 | 11 | [Descargar un archivo: flujos, ventanas y SENDME](Laboratorio-05-Flujos.md) | Sí |
| 6 | 12 | [Descargar y verificar el consenso](Laboratorio-06-Directorio.md) | Sí |
| 7 | 13 | [Selección ponderada por ancho de banda](Laboratorio-07-Rutas.md) | No |
| 8 | 14 | [Localizar y leer un descriptor onion](Laboratorio-08-Onion.md) | Sí |
| 9 | 15 | [Activar las defensas contra DoS](Laboratorio-09-DoS.md) | Sí |
| 10 | 16 | [Un puente obfs4 desde la perspectiva de un censor](Laboratorio-10-Puente.md) | Red independiente |
| 11 | 18 | [Aislamiento de flujos en directo](Laboratorio-11-Aislamiento.md) | Sí |
| 12 | 20 | [Celdas dentro de TLS](Laboratorio-12-Trafico.md) | Sí |
| 13 | 21 | [Servicio onion con descubrimiento restringido](Laboratorio-13-Descubrimiento-restringido.md) | Sí |
| 14 | 22 | [Probar una política de salida](Laboratorio-14-Politica-de-salida.md) | Sí |
| 15 | 24 | [Estadísticas de red a partir de un consenso](Laboratorio-15-Metricas.md) | No |
| 16 | 26 | [Correlacionar tu propio tráfico](Laboratorio-16-Correlacion.md) | Sí |
| 17 | 27 | [El límite de celdas RELAY_EARLY](Laboratorio-17-Relay-early.md) | Sí |
| 18 | 28 | [Tor detecta un indicio de filtración DNS](Laboratorio-18-Fuga-DNS.md) | Sí |
| 19 | 29 | [Tiempo hasta el primer compromiso](Laboratorio-19-Simulacion.md) | No |
| 20 | 30 | [Arti en la red privada](Laboratorio-20-Arti.md) | Sí |

Los laboratorios 1–8 introducen gradualmente el cliente `torlab`; conviene seguirlos en orden, puesto que reutilizan los módulos anteriores. Los posteriores son en gran medida independientes.

## Qué contiene cada guía

Cada página explica el objetivo, la preparación, los comandos, los resultados de referencia y su interpretación, la verificación prevista y los problemas conocidos.

Los laboratorios 1–8 incluyen además una sección de **implementación detallada**, con funciones explicadas paso a paso, decisiones de diseño, errores que conviene evitar y correspondencias entre el código y las especificaciones. El libro describe el protocolo; estas páginas describen su implementación.

Las salidas conservadas son referencias históricas del entorno con tor 0.4.9.13, no resultados nuevos validados para la edición española. Los valores de claves, direcciones, tiempos y capturas pueden variar; las cifras de los laboratorios 7, 15 y 19 requieren los datos históricos correspondientes.

El entorno español se mantiene separado en `labs/es/`; la documentación está en `labs/es/wiki/`. Las implementaciones de otros idiomas no forman parte del entorno de ejecución español.
