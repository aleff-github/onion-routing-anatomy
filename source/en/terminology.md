# English terminology

This file records terminology decisions for the English edition. Official
protocol terms must not be replaced with editorial synonyms.

| Italian source term | English term | Rule |
|---|---|---|
| onion routing | onion routing | Keep the official term. |
| relay | relay | Do not replace with router or node except in a generic explanation. |
| nodo guard | guard relay / guard | Use guard when the role is clear. |
| nodo intermedio | middle relay / middle | Use middle in protocol descriptions. |
| nodo di uscita | exit relay / exit | Use exit in protocol descriptions. |
| cella | cell | Keep protocol command tokens such as `VERSIONS` and `RELAY` unchanged. |
| cella RELAY | RELAY cell | Distinguish the cell type from the relay message/command inside it. |
| circuito | circuit | |
| stream | stream | |
| canale | channel | |
| link protocol | link protocol | Do not shorten to transport protocol. |
| handshake | handshake | |
| directory authority | directory authority | |
| consenso | consensus | |
| descrittore | descriptor | |
| microdescrittore | microdescriptor | |
| onion service | onion service | Use hidden service only for historical context. |
| punto di introduzione | introduction point | |
| punto di rendezvous | rendezvous point | |
| bridge | bridge | |
| pluggable transport | pluggable transport | |
| chiave accecata | blinded key | |
| chiave di famiglia | family key | Shared relay-family membership key; do not confuse with an onion-service blinded key. |
| forward secrecy | forward secrecy | The Italian source also uses this official English term; compromise of a long-term key must not reveal previously recorded traffic. |
| analisi del traffico | traffic analysis | |
| fingerprinting dei siti web | website fingerprinting | Recognizing visited sites/pages from encrypted traffic features, not from plaintext URLs. |
| correlazione del traffico | traffic correlation | |
| controllo del flusso | flow control | Receiver-side windows and SENDME; distinct from congestion control. |
| controllo della congestione | congestion control | Adapts the amount of data in flight to network conditions; not synonymous with flow control. |
| proposta | proposal | Preserve the proposal number. |

The English edition uses clear technical prose, short sentences, and a calm
university-textbook register. It keeps the original teaching progression:
motivation -> mechanism -> low-level detail -> concrete example.
