# Laboratorio 2 — Codificare e decodificare celle

| | |
|---|---|
| **Capitolo** | 8 — Celle: il formato di base |
| **Serve la rete?** | no |
| **Prerequisiti** | Python 3.11 o successivo |
| **Tempo** | 1–2 ore per scriverlo, 2 minuti per rieseguirlo |
| **File** | `labs/it/codice/torlab/celle.py`, `labs/it/codice/torlab/test/test_celle.py` |

## Che cosa dimostra

La misura **514 byte** riguarda le celle fisse dal link protocol 4 in poi; nella versione 3 il CircID occupa 2 byte e la cella fissa misura **512 byte**.

Che una cella Tor è una struttura semplice e rigida: 4 byte di CircID, 1 di comando,
509 di corpo, in tutto **514 byte**, sempre gli stessi qualunque cosa trasporti. È questa
uniformità a impedire che la dimensione delle celle riveli il contenuto. Le celle a
lunghezza variabile (`VERSIONS` e tutti i comandi ≥ 128) sono l'eccezione, e `VERSIONS`
usa sempre un CircID di 2 byte, perché viene scambiata prima che la versione del link
protocol sia nota.

## Preparazione

Nessuna. Serve solo il codice del repository:

```bash
cd /percorso/del/repository
export PYTHONPATH=labs/it/codice
```

## Esecuzione

```bash
python3 - <<'EOF'
from torlab.celle import *

# 1. una cella a lunghezza fissa
c = Cella(0x80000001, Comando.RELAY, b"\x01" * 509)
g = codifica(c, 4)
print("lunghezza:", len(g), "| primi 8 byte:", g[:8].hex())

# 2. decodifica: restituisce la cella e i byte avanzati
letta, resto = decodifica(g, 4)
print("riletta:", hex(letta.circ_id), Comando(letta.comando).name, "| resto:", len(resto))

# 3. una cella a lunghezza variabile
print("VERSIONS:", codifica(Cella(0, Comando.VERSIONS, b"\x00\x04\x00\x05"), 4).hex())

# 4. un messaggio relay dentro il corpo di una cella
m = MessaggioRelay(ComandoRelay.BEGIN, 1, b"127.0.0.1:80\x00")
r = codifica_relay(m)
print("messaggio relay:", len(r), "byte | intestazione:", r[:11].hex())
rit = decodifica_relay(r)
print("riletto:", ComandoRelay(rit.comando).name, rit.stream_id, rit.dati)
EOF
```

## Output atteso

```
lunghezza: 514 | primi 8 byte: 8000000103010101
riletta: 0x80000001 RELAY | resto: 0
VERSIONS: 000007000400040005
messaggio relay: 509 byte | intestazione: 010000000100000000000d
riletto: BEGIN 1 b'127.0.0.1:80\x00'
```

Come leggerlo:

- `8000000103` = CircID `0x80000001` (il bit alto è a uno perché il circuito è stato
  creato da noi, che siamo l'iniziatore del canale) seguito dal comando `3` (`RELAY`).
- La cella `VERSIONS` è `0000` (CircID a **2** byte) + `07` (comando) + `0004`
  (lunghezza) + `0004 0005` (le versioni 4 e 5 offerte).
- L'intestazione del messaggio relay è `01` (`BEGIN`), `0000` (`Recognized`),
  `0001` (StreamID), `00000000` (Digest, ancora vuoto: lo riempirà la cifratura del
  Laboratorio 4), `000d` (13 byte di dati).

`Cella.comando` e `MessaggioRelay.comando` sono interi: per stamparne il nome si
convertono con `Comando(...)` e `ComandoRelay(...)`.

## Verifica automatica

```bash
cd codice && python3 -m pytest -q torlab/test/test_celle.py      # 7 test
```

I test coprono i casi che contano davvero: la lunghezza delle celle nelle versioni 3 e 4
del link protocol (512 e 514 byte), il CircID di 2 byte della `VERSIONS`, un flusso
frammentato in cui la prima cella è incompleta e `decodifica` deve restituire `None`
invece di sollevare un'eccezione, la negoziazione della versione con offerte malformate,
l'accettazione di un `DESTROY` con motivo 0 e il rifiuto di un `DESTROY` con CircID uguale a 0, i dati relay più lunghi di 498 byte, e il
riempimento di un messaggio relay: quattro zeri e poi byte casuali, come prescrive la
specifica.

Il controllo corrispondente in `make verifica-lab` è la funzione `lab2`.

## Problemi noti

Nessuno. È l'unico laboratorio senza dipendenze esterne: se questo non funziona, il
problema è l'installazione di Python.

---

# Il codice, in dettaglio

Tutto il laboratorio sta in `labs/it/codice/torlab/celle.py`, circa 220 righe. È il modulo su cui
si appoggiano tutti gli altri: se qui c'è un errore, si manifesta tre laboratori più
avanti sotto forma di un circuito che il relay chiude senza spiegazioni.

## Le costanti

```python
CELL_BODY_LEN = 509          # byte di corpo di una cella a lunghezza fissa
RELAY_HEADER_LEN = 11        # intestazione di un messaggio relay
RELAY_DATA_MAX = CELL_BODY_LEN - RELAY_HEADER_LEN   # 498
```

`RELAY_DATA_MAX` non è una costante della specifica: è una **conseguenza**. Scriverla come
differenza invece che come `498` fa sì che resti giusta se una delle due cambia — e non è
un'ipotesi di scuola: la cifratura CGO (proposta 359, già nel codice di tor) usa
un'intestazione diversa, e la proposta 340 separerebbe del tutto i messaggi dalle celle.

I comandi sono `IntEnum`, non `Enum`. La differenza conta: devono potersi confrontare e
impacchettare come interi (`bytes([cella.comando])` funziona solo così), ma stampandoli si
legge il nome. Per un protocollo binario è il compromesso giusto.

```python
def circid_len(versione):
    return 2 if versione < 4 else 4

def lunghezza_variabile(comando):
    return comando == Comando.VERSIONS or comando >= 128
```

La larghezza del CircID dipende dalla versione del link protocol negoziata: 2 byte fino
alla 3, 4 dalla 4 in poi. Isolarla in una funzione evita di spargere il numero magico per
tutto il modulo.

La regola «≥ 128» non è una convenzione nostra: è della specifica. Il bit alto del comando
**è** il segnale che la cella ha lunghezza variabile. `VERSIONS` (7) è l'unica eccezione,
per ragioni storiche: esisteva prima che la convenzione fosse introdotta.

## `codifica`

```python
def codifica(cella, versione):
    if cella.comando == Comando.VERSIONS:
        versione = 0
    n = circid_len(versione)
    if not 0 <= cella.circ_id < 1 << (8 * n):
        raise ErroreCella(f"CircID {cella.circ_id:#x} non sta in {n} byte")
    intestazione = cella.circ_id.to_bytes(n, "big") + bytes([cella.comando])
    if lunghezza_variabile(cella.comando):
        if len(cella.corpo) > 0xFFFF:
            raise ErroreCella("corpo troppo lungo per una cella variabile")
        return intestazione + struct.pack(">H", len(cella.corpo)) + cella.corpo
    if len(cella.corpo) > CELL_BODY_LEN:
        raise ErroreCella(f"corpo di {len(cella.corpo)} byte > {CELL_BODY_LEN}")
    return intestazione + cella.corpo.ljust(CELL_BODY_LEN, b"\x00")
```

**Il caso particolare che sorprende tutti** sono le prime due righe. La `VERSIONS` si
scambia *prima* che una versione sia stata concordata, quindi non può usarne il formato:
sarebbe un problema dell'uovo e della gallina. Forzando `versione = 0` si ottiene un
CircID di 2 byte, come prescrive la specifica. È l'unica cella il cui formato non dipende
dalla negoziazione — se dipendesse, non ci sarebbe modo di iniziarla.

`"big"` è l'ordine di rete, quello di tutti i campi numerici di Tor. Il controllo
sull'intervallo del CircID è ridondante (`to_bytes` solleverebbe `OverflowError` da solo)
ma dà un messaggio che dice quale numero e quanti byte: in un modulo didattico il messaggio
d'errore è parte della spiegazione.

Le due famiglie divergono qui:

- **variabile**: si scrive il proprio `Length` su 2 byte e poi il corpo così com'è. Non c'è
  niente da riempire, perché la lunghezza è dichiarata.
- **fissa**: si riempie **di zeri** fino a 509 byte. Lo impone la specifica, e chi riceve
  deve ignorare quei byte.

> **Non confondere questo riempimento con quello dei messaggi relay** (più sotto), che
> segue una regola diversa e per una ragione diversa. Qui i byte in più stanno dentro il
> TLS e nessun relay intermedio li vede in chiaro; là no.

## `decodifica`

**Attenzione a `VERSIONS`:** in ricezione, prima della negoziazione, chiama `decodifica(buffer, 0)` per usare il CircID a due byte. Solo dopo l'accordo sulla versione usa `decodifica(buffer, versione_negoziata)`. Il parametro della funzione controlla il formato delle celle in arrivo.

```python
def decodifica(buffer, versione):
    n = circid_len(versione)
    if len(buffer) < n + 1:
        return None
    circ_id = int.from_bytes(buffer[:n], "big")
    comando = buffer[n]
    if lunghezza_variabile(comando):
        if len(buffer) < n + 3:
            return None
        (lunghezza,) = struct.unpack(">H", buffer[n + 1:n + 3])
        fine, inizio_corpo = n + 3 + lunghezza, n + 3
    else:
        fine, inizio_corpo = n + 1 + CELL_BODY_LEN, n + 1
    if len(buffer) < fine:
        return None
    return Cella(circ_id, comando, buffer[inizio_corpo:fine]), buffer[fine:]
```

È scritta per essere chiamata **ogni volta** che arrivano byte dal socket, senza sapere se
bastano. Ci sono **tre** controlli di sufficienza, ed è il punto in cui una decodifica
ingenua va in `IndexError` sul traffico reale:

1. senza CircID e comando non si sa nemmeno di che tipo di cella si tratti;
2. per una cella variabile servono altri 2 byte prima di conoscere la lunghezza;
3. infine, il corpo dev'essere tutto arrivato.

`None` significa «richiamami quando avrai altri byte», non «errore». È la differenza che
tiene pulito il codice del chiamante, che diventa:

```python
while True:
    esito = decodifica(buffer, versione)
    if esito is None:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("connection closed before a complete cell")
        buffer += chunk
        continue
    cella, buffer = esito
    ...
```

Restituire anche `buffer[fine:]` — ciò che avanza — è quello che permette di decodificare
più celle di fila da uno stesso blocco di byte, che è il caso **normale**: un record TLS ne
contiene fino a 31 (capitolo 11).

Non usiamo un parser a stati né una coda: il buffer è un oggetto `bytes` e ogni chiamata ne
consuma un pezzo. Su un client didattico è la scelta più leggibile; un'implementazione vera
userebbe un buffer circolare per non ricopiare i byte residui a ogni cella. Con celle da
514 byte e ricopiature continue, su un relay reale la differenza si misura.

## `negozia_versione`

```python
def negozia_versione(mie, corpo_ricevuto):
    if len(corpo_ricevuto) % 2:
        raise ErroreCella("VERSIONS con un numero dispari di byte")
    sue = {v for (v,) in struct.iter_unpack(">H", corpo_ricevuto)}
    comuni = set(mie) & sue
    if not comuni:
        raise ErroreCella("nessuna versione del link protocol in comune")
    return max(comuni)
```

Un corpo di lunghezza dispari non può essere un elenco di interi da 2 byte: il documento è
malformato e si rifiuta subito, invece di indovinare. Poi l'intersezione, e il **massimo**:
è la regola della specifica, «il numero più alto contenuto sia nella `VERSIONS` inviata sia
in quella ricevuta».

Viene naturale chiedersi che cosa impedisca un **downgrade**, cioè che qualcuno tolga
dall'elenco le versioni recenti per far concordare la più bassa. Questa funzione, da sola,
non se ne accorgerebbe. La risposta sta fuori:

- lo scambio avviene già dentro il TLS, e il canale è legato all'identità del relay dalla
  cella `CERTS` ([Laboratorio 1](Laboratorio-01-Canale.md));
- quando l'iniziatore è a sua volta un relay e si autentica, il digest dell'`AUTHENTICATE`
  copre **tutti** i byte scambiati, `VERSIONS` compresa. Un'alterazione, lì, si vedrebbe.

## `codifica_relay`

```python
def codifica_relay(msg, casuale=os.urandom):
    if len(msg.dati) > RELAY_DATA_MAX:
        raise ErroreCella(f"al massimo {RELAY_DATA_MAX} byte di dati per cella")
    intestazione = struct.pack(">BHH4sH", msg.comando, msg.recognized,
                               msg.stream_id, msg.digest, len(msg.dati))
    spazio = CELL_BODY_LEN - RELAY_HEADER_LEN - len(msg.dati)
    padding = b"\x00" * min(4, spazio) + casuale(max(0, spazio - 4))
    return intestazione + msg.dati + padding
```

Un solo `struct.pack` per tutti e cinque i campi. Il formato `">BHH4sH"` si legge da
sinistra come la figura del capitolo 8: comando (1 byte), `Recognized` (2), StreamID (2),
Digest (4 byte grezzi, da cui `4s`), `Length` (2). Totale 11, cioè `RELAY_HEADER_LEN`.

Il riempimento relay contiene **fino a quattro byte zero e poi byte casuali**, se c'è spazio. La specifica lo raccomanda (SHOULD); quando restano meno di quattro byte, sono tutti zeri. Il riempimento non prova da solo che il messaggio sia riconosciuto: servono le verifiche `Recognized` e `Digest`.

| | celle a lunghezza fissa | messaggi relay |
|---|---|---|
| riempimento | tutti zeri | fino a 4 zeri, poi byte casuali se c'è spazio |
| chi lo vede in chiaro | il peer TLS immediato dopo aver decifrato il collegamento, non gli osservatori esterni | il nodo che riconosce e decifra il messaggio relay |
| a che serve | riempire | rendere il contenuto imprevedibile |

Se il riempimento fosse di zeri, un avversario che riesca a indovinare i dati saprebbe
anche il resto del corpo, e ridurrebbe l'imprevedibilità dei digest usati dai `SENDME` autenticati della proposta 289
([Laboratorio 5](Laboratorio-05-Stream.md)). Gli zeri iniziali non costituiscono un criterio autonomo di riconoscimento: il destinatario deve verificare `Recognized` e `Digest`
([Laboratorio 4](Laboratorio-04-Cifratura.md)).

Il parametro `casuale` esiste solo per i test: permette di sostituire i byte casuali con
valori prevedibili. Senza quell'iniezione, l'unica cosa verificabile sarebbe la lunghezza.
È un esempio di una regola generale che ritorna in tutto il repository: **il non
determinismo va iniettato, non incorporato**, altrimenti il codice non è verificabile.

## Da dove vengono questi formati

Ogni riga del modulo traduce un punto preciso della specifica. Se qualcosa non torna, la
fonte è questa, non questa pagina:

| Nel codice | Nella specifica (spec.torproject.org) |
|---|---|
| lunghezze e formato delle celle | tor-spec, *Cells (messages on channels)* |
| riempimento a zeri | tor-spec, *Padding fixed-length cell bodies* |
| `VERSIONS` e negoziazione | tor-spec, *Negotiating versions with VERSIONS cells* |
| intestazione del messaggio relay | tor-spec, *Relay cells* |
| 4 zeri + casuale | tor-spec, *Relay cells* (rationale: proposta 289) |
| elenco dei comandi | tor-spec, tabelle in *Cells* e *Relay cells* |
