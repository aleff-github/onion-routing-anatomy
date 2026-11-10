# Terminología editorial — Edición en español

Idioma: **español internacional**, con terminología técnica comprensible en España y América Latina. Mantener los nombres propios, identificadores binarios, nombres de API, campos de protocolo y títulos originales de los trabajos científicos.

| Término inglés | Traducción editorial | Criterio |
|---|---|---|
| onion routing | encaminamiento cebolla | La primera vez puede indicarse *onion routing* entre paréntesis. |
| relay | repetidor | Para el papel de Tor; no traducir como encaminador salvo contexto genérico. |
| guard relay / guard | repetidor de entrada / guardia | Mantener *guard* como identificador del protocolo cuando sea necesario. |
| middle relay | repetidor intermedio | En una ruta o circuito. |
| exit relay | repetidor de salida | También «salida» si el contexto es inequívoco. |
| cell | celda (*cell*) | En código y nombres de comandos mantener `Cell` y `RELAY`. |
| circuit | circuito | Ruta lógica de varios saltos. |
| stream | flujo | Flujo de aplicación multiplexado dentro de un circuito. |
| channel | canal | Conexión subyacente entre nodos. |
| link protocol | protocolo de enlace | Protocolo Tor versionado sobre el canal TLS, distinto del transporte conectable (*pluggable transport*). |
| handshake | intercambio inicial / handshake | Como en el capítulo 7, puede designar la negociación del canal Tor tras TLS; distinguirla del *handshake* TLS y del intercambio de claves ntor. No traducir siempre como «intercambio de claves». |
| directory authority | autoridad de directorio | |
| consensus | consenso | |
| descriptor | descriptor | |
| microdescriptor | microdescriptor | |
| onion service | servicio onion | Mantener «onion» como denominación estable del servicio. |
| introduction point | punto de introducción | |
| rendezvous point | punto de encuentro | |
| bridge | puente | |
| pluggable transport | transporte conectable | Primera aparición: «transporte conectable (*pluggable transport*)». |
| blinded key | clave cegada | Consistencia con conceptos criptográficos; alternativamente «clave sometida a cegado». |
| family key | clave de familia | Clave de pertenencia de los repetidores a una familia, distinta de la clave cegada de un servicio onion. |
| forward secrecy | secreto hacia adelante | «Secreto hacia adelante» o «confidencialidad futura» con explicación contextual. |
| traffic analysis | análisis de tráfico | |
| traffic correlation | correlación de tráfico | |
| flow control | control de flujo | Ventanas y mensajes SENDME para no desbordar al receptor; no es sinónimo de control de congestión. |
| congestion control | control de congestión | Adapta los datos en tránsito a la situación de la red; no equivale al control de flujo. |
| threat model | modelo de amenazas | |
| unlinkability | desvinculación | Puede aclararse como «imposibilidad de vincular». |
| unobservability | no observabilidad | |
| anonymity set | conjunto de anonimato | |
| pseudonymity | seudonimato | Preferir seudónimo/seu- en español moderno. |
| proposal | propuesta | Conservar los números de propuesta y los identificadores de torspec. |

Convenciones LaTeX: **no traducir** nombres de macros ni etiquetas `\label{}`, claves de `\cite{}`, valores de celdas binarias o vectores de prueba. Traducir íntegramente la prosa, los pies de figura, el texto alternativo de imágenes, las preguntas, soluciones y los resultados presentados al lector; conservar los registros originales del software externo cuando sea necesario para compararlos con la ejecución real.
