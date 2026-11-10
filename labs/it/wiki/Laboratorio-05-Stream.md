# Laboratorio 5 — Scaricare un file: stream, finestre e SENDME

| | |
|---|---|
| **Capitolo** | 11 — Stream e controllo di flusso |
| **Serve la rete?** | sì, più un server web locale |
| **Prerequisiti** | Laboratori 1–4 |
| **Tempo** | 3 ore per scriverlo, 2 minuti per rieseguirlo |
| **File** | `labs/it/codice/torlab/stream.py` |

## Che cosa dimostra

Che il client didattico scarica davvero un megabyte attraverso tre relay, con l'impronta
SHA-256 identica all'originale. E poi un esperimento che nessun client normale può fare:
**smettere di inviare `SENDME`** e contare quante celle l'exit manda prima di fermarsi.
Quel numero è la finestra, e si vede a occhio nudo la differenza fra il controllo di
flusso storico e il controllo della congestione.

## Preparazione

Il laboratorio va eseguito esclusivamente sulla **rete Tor privata Chutney** avviata nei Laboratori 1–4. Se la rete non è attiva, avvia prima l'ambiente corrispondente alla tua edizione; il client didattico non va usato sulla rete Tor pubblica. Il web server deve essere raggiungibile attraverso il loopback del relay del laboratorio.

Serve un server web locale sulla porta 8080 con un file da un megabyte:

```bash
mkdir -p /tmp/labweb && head -c 1048576 /dev/urandom > /tmp/labweb/grande.bin
sha256sum /tmp/labweb/grande.bin
cd /tmp/labweb && python3 -m http.server 8080 --bind 127.0.0.1 &
```

Poi, dal repository:

```bash
export PYTHONPATH=labs/it/codice
```

> La porta 8080 serve anche a `make verifica-lab`: ricordati di chiudere questo server
> prima di lanciarlo, altrimenti la suite si ferma subito dicendolo.

## Esecuzione

```bash
python3 - <<'EOF'
import hashlib
import time
from pathlib import Path
from torlab.circuito import costruisci
from torlab.laboratorio import relay
from torlab.stream import Stream

circ = costruisci([relay("003r"), relay("004r"), relay("006e")])
s = Stream(circ, 1)
t = time.time()
s.apri("127.0.0.1", 8080)
s.invia(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
r1 = s.ricevi_tutto()
print(f"stream 1: {len(r1)} byte in {time.time()-t:.2f} s, celle DATA {s.reg.celle_data}, "
      f"SENDME del circuito finora {circ.sendme_inviati}, altri {s.reg.altri}")

s = Stream(circ, 2)
t = time.time()
s.apri("127.0.0.1", 8080)
s.invia(b"GET /grande.bin HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
r2 = s.ricevi_tutto()
print(f"stream 2: {len(r2)} byte in {time.time()-t:.2f} s, celle DATA {s.reg.celle_data}, "
      f"SENDME del circuito finora {circ.sendme_inviati}, altri {s.reg.altri}")

intestazioni, separatore, dati = r2.partition(b"\r\n\r\n")
if not separatore or b" 200 " not in intestazioni.split(b"\r\n", 1)[0]:
    raise RuntimeError("risposta HTTP assente o diversa da 200 OK")
originale = Path("/tmp/labweb/grande.bin").read_bytes()
assert len(originale) == len(dati) == 1048576, "lunghezza del file non valida"
attesa = hashlib.sha256(originale).hexdigest()
ricevuta = hashlib.sha256(dati).hexdigest()
assert ricevuta == attesa, "SHA-256 del download diverso dall'originale"
print("sha256 ricevuto:", ricevuta)
print("SHA-256 verificato sul file locale")
EOF
```

## Output atteso

L'output qui sotto è **illustrativo**, non una nuova esecuzione: il file è generato casualmente, e intestazioni HTTP, tempi e celle DATA possono variare. Il codice controlla davvero il codice di stato HTTP, la lunghezza del file e l'impronta SHA-256.

```text
stream 1: ... celle DATA 1, SENDME del circuito finora 0, ...
stream 2: ... celle DATA 2120, SENDME del circuito finora 68, ...
sha256 ricevuto: <impronta SHA-256 esadecimale a 64 caratteri>
SHA-256 verificato sul file locale
```

Una risposta `CONNECTED` IPv4 **può** contenere un corpo di otto byte (indirizzo e TTL), per esempio `7f000001 00000708`. La specifica ammette anche un corpo vuoto o un formato IPv6: non sono costanti il corpo e il TTL. Il contatore dei SENDME di circuito riguarda le celle DATA **originate dall'ultimo salto per i suoi stream**, non tutte le celle soltanto inoltrate dai relay intermedi.

Nell'esempio storico 1 + 2120 celle DATA, confermate ogni 31, danno `floor(2121 / 31) = 68` SENDME. Per una risposta HTTP da 1048781 byte servono almeno `ceil(1048781 / 498) = 2106` celle; averne 2120 illustra il possibile impacchettamento parziale, non una regola.

## L'errore che vale il laboratorio

Nella prima versione il contatore dei `SENDME` era un attributo dello **stream**. Il
primo stream, due celle, funzionava. Il secondo, un megabyte, veniva interrotto
dall'exit con un `DESTROY`.

Il motivo: il `SENDME` di circuito conta le celle `DATA` di *tutti* gli stream. L'exit
aveva già contato le due del primo stream e aspettava il `SENDME` alla 29ª cella del
secondo; noi lo inviavamo alla 31ª, con un digest diverso da quello atteso, e l'exit ha
fatto ciò che la proposta 289 prescrive: ha chiuso il circuito. Spostare il contatore
nella classe `Circuito` ha risolto.

I `SENDME` di circuito sono **autenticati**: contengono il digest progressivo della
cella che li fa scattare. Un attaccante che non vede il traffico non può fabbricarli per
far accelerare il mittente.

## Le finestre, viste da dentro

```bash
python3 - <<'EOF'
from torlab.circuito import costruisci
from torlab.laboratorio import relay
from torlab.stream import Stream
for cc in (True, False):
    circ = costruisci([relay("003r"), relay("004r"), relay("006e")], cc=cc)
    circ.conta_data_ricevuto = lambda: None       # non inviamo mai SENDME
    s = Stream(circ, 1)
    s.apri("127.0.0.1", 8080)
    s.invia(b"GET /grande.bin HTTP/1.0\r\n\r\n")
    circ.canale.sock.settimeout(6)
    try:
        s.ricevi_tutto()
    except TimeoutError:
        pass
    print(f"controllo della congestione={cc}: l'exit si ferma dopo {s.reg.celle_data} celle DATA")
EOF
```


```text
controllo della congestione=True: l'exit si ferma dopo 124 celle DATA
controllo della congestione=False: l'exit si ferma dopo 500 celle DATA
```

Questi **valori sono storici e dipendono dalla configurazione**: 124 è la finestra iniziale di congestione di quattro incrementi da 31 DATA, **non esattamente quattro record TLS**; 500 è la finestra di stream storica che si esaurisce prima della finestra di circuito nominale da 1000. Parametri di consenso e versione di Tor possono produrre numeri diversi. Quando la finestra si esaurisce l'exit sospende l'origine di nuove DATA; non è corretto dedurre che tutti i byte non ancora spediti siano necessariamente nel buffer applicativo dell'exit.

**Limite didattico importante:** `Stream` non implementa `SENDME` di stream. Va bene quando l'exit ha negoziato il controllo della congestione (`cc=True`); con `cc=False` un download lungo resta bloccato dopo 500 celle anche se i SENDME del circuito funzionano. Per questo la prova senza congestione misura la finestra, ma non dimostra il funzionamento di un client legacy completo.
## Verifica automatica

Il verificatore italiano `lab5` in `scripts/verify_labs.py` confronta l'impronta e controlla le due finestre nell'ambiente privato per cui è stato scritto. Non è una garanzia universale sui valori 124/500, e richiede la rete Chutney avviata.

## Problemi noti

| Sintomo | Causa |
|---|---|
| `BEGIN rifiutato: EXITPOLICY` | l'exit rifiuta l'indirizzo o la porta: controlla le modifiche del [Laboratorio 14](Laboratorio-14-Politica-di-uscita.md) |
| Il circuito viene distrutto durante un download grande | contatore dei `SENDME` per stream anziché per circuito (vedi sopra) |
| `BEGIN rifiutato: CONNECTREFUSED` | l'exit non riesce a connettersi a 127.0.0.1:8080: controlla il server web locale |

---

# Il codice, in dettaglio

`labs/it/codice/torlab/stream.py` (~80 righe) e la parte di `circuito.py` che gestisce i `SENDME`.
È il laboratorio in cui il client didattico smette di essere un esercizio e comincia a
scaricare file veri.

## Aprire uno stream

```python
def corpo_begin(indirizzo: str, porta: int, flag: int = 0) -> bytes:
    """ADDRPORT terminato da NUL, in minuscolo; FLAGS omesso se vale zero."""
    corpo = f"{indirizzo.lower()}:{porta}".encode() + b"\x00"
    return corpo + (struct.pack(">I", flag) if flag else b"")

```

Tre dettagli, con differente forza normativa:

- **minuscolo (SHOULD)**: la specifica raccomanda di inviare `ADDRPORT` in minuscolo per ridurre il fingerprinting, ma il ricevente **deve (MUST)** accettare anche lettere maiuscole. Non è un obbligo di rifiuto.
- **terminato da NUL**: il campo è una stringa C, non ha un campo lunghezza.
- **FLAGS omesso se vale zero**: il campo è facoltativo, e i flag servono solo a dichiarare
  il supporto per IPv6.

```python
def apri(self, indirizzo: str, porta: int) -> bytes:
    self.circ.invia(MessaggioRelay(ComandoRelay.BEGIN, self.id, corpo_begin(indirizzo, porta)))
    _, msg = self._prossimo()
    if msg.comando == ComandoRelay.END:
        raise ErroreCircuito(f"BEGIN rifiutato: {MOTIVI_END.get(msg.dati[0], msg.dati[0])}")
    if msg.comando != ComandoRelay.CONNECTED:
        raise ErroreCircuito(f"risposta inattesa a BEGIN: {msg.comando}")
    return msg.dati
```

Qui c'è una differenza dichiarata fra il nostro client e tor, e conviene conoscerla perché
riguarda l'impronta del client. La specifica (`tor-spec`, *Handling RELAY_EARLY cells*)
obbliga a inviare `EXTEND2` in una cella `RELAY_EARLY`, e **raccomanda** di inviare così
anche le prime otto celle circa non dirette al primo salto, per non rivelare la lunghezza
del circuito a chi osserva il canale. tor lo fa: in `src/core/or/relay.c` usa una
`RELAY_EARLY` per qualsiasi cella con `cpath_layer != origin_circ->cpath` finché
`remaining_relay_early_cells > 0`. Quindi tor manda il `BEGIN` in una `RELAY_EARLY`, mentre
il nostro `apri` usa una `RELAY` ordinaria: `invia` mette `early=True` solo per `EXTEND2`.
La conseguenza è reale: un guard che conta le `RELAY_EARLY` distingue il nostro client da
tor. Non l'abbiamo cambiato perché il codice resti leggibile su un punto alla volta, ma è
esattamente il genere di dettaglio da cui nasce un'impronta — e il libro lo mostra nella
figura della sessione completa, dove il `BEGIN` viaggia come `RELAY_EARLY`.

L'exit risponde `CONNECTED` con un corpo di 8 byte — indirizzo risolto e TTL — oppure `END`
con un motivo. I motivi stanno in `MOTIVI_END`, e leggerli è metà del
[Laboratorio 14](Laboratorio-14-Politica-di-uscita.md): `EXITPOLICY` significa «questo exit non
serve questa destinazione, cambiane uno», `CONNECTREFUSED` significa «l'ho raggiunta e ha
detto di no», e le due cose portano a decisioni opposte.

Si possono inviare dati **prima** di ricevere `CONNECTED`: il protocollo lo permette, e
serve a risparmiare un giro completo del circuito. Il nostro codice non lo fa, per
leggibilità.

## Il controllo di flusso, e l'errore che vale il laboratorio

```python
def conta_data_ricevuto(self) -> None:
    """Da chiamare per ogni cella DATA ricevuta dall'ultimo salto: invia un SENDME
    autenticato (versione 1) ogni `sendme_inc` celle."""
    est = dict(self.estensioni_exit)
    sendme_inc = est[2][0] if 2 in est else 100
    self.data_da_confermare += 1
    if self.data_da_confermare == sendme_inc:
        self.data_da_confermare = 0
        # Il digest è quello progressivo dopo l'ultima cella riconosciuta (quella che
        # fa scattare il SENDME): sendme_digest in src/core/crypto/relay_crypto_tor1.c.
        digest = self.cripto.salti[-1].indietro.digest.digest()
        corpo = struct.pack(">BH", 1, 20) + digest
        self.invia(MessaggioRelay(ComandoRelay.SENDME, 0, corpo))
        self.sendme_inviati += 1
```

**Il metodo sta su `Circuito`, non su `Stream`.** Nella prima versione di questo laboratorio
il contatore era un attributo dello stream. Il primo stream, una pagina di due celle,
funzionava; il secondo, un file da un megabyte, veniva interrotto dall'exit con un
`DESTROY`.

Il motivo: il `SENDME` di circuito conta le celle `DATA` di **tutti** gli stream del
circuito. L'exit aveva già contato le due celle del primo stream e si aspettava il `SENDME`
alla 29ª cella del secondo; noi lo inviavamo alla 31ª, con un digest diverso da quello
atteso, e l'exit ha fatto ciò che la proposta 289 prescrive: ha chiuso il circuito.

Gli altri elementi della funzione:

- **`sendme_inc`** si legge dall'estensione 2 negoziata con l'exit durante l'handshake
  ([Laboratorio 3](Laboratorio-03-Handshake.md)): vale 31 con il controllo della congestione,
  100 con il controllo di flusso storico. Non è una costante del codice: è una cosa che
  l'exit ci ha detto.
- **Il digest** è quello progressivo dell'ultimo salto in direzione di ritorno, *dopo* la
  cella che fa scattare il `SENDME`. Non è un valore che scegliamo: è lo stato interno della
  cifratura, e solo chi ha davvero ricevuto e decifrato quelle celle lo conosce.
- **Versione 1 e lunghezza 20** (SHA-1). La versione 0 non portava digest, e chiunque poteva
  fabbricare `SENDME` per far accelerare il mittente: è l'attacco che la proposta 289 chiude.
- **StreamID zero**: è un messaggio di controllo del circuito. Gli stream hanno i propri
  `SENDME`, con StreamID e finestra separati.

> Il `SENDME` autenticato non è una firma: è una **prova di aver ricevuto**. Solo chi ha
> decifrato le celle conosce quel digest, quindi solo chi le ha ricevute può chiedere di
> riceverne altre.

## Il ciclo di ricezione

```python
def ricevi_tutto(self) -> bytes:
    """Legge DATA fino a END, inviando i SENDME di circuito quando dovuto."""
    parti = []
    while not self.chiuso:
        _, msg = self._prossimo()
        if msg.comando == ComandoRelay.DATA:
            parti.append(msg.dati)
            self.reg.dati_ricevuti += len(msg.dati)
            self.reg.celle_data += 1
            self.circ.conta_data_ricevuto()
        elif msg.comando == ComandoRelay.END:
            self.chiuso = True
            self.reg.altri.append(f"END {MOTIVI_END.get(msg.dati[0] if msg.dati else 1)}")
        else:
            self.reg.altri.append(ComandoRelay(msg.comando).name)
    return b"".join(parti)
```

Il conteggio e il `SENDME` stanno **dentro** il ciclo di ricezione, non in un thread a
parte: finché non si legge, non si conferma, e quindi non si chiede altro. È il controllo di
flusso che funziona da sé.

`self.reg` accumula statistiche (byte, celle `DATA`, altri messaggi visti): servono a
stampare la riga di riepilogo del laboratorio e a far vedere che le celle sono più delle
⌈byte/498⌉ minime, perché l'exit impacchetta man mano che legge dal server invece di
aspettare di riempire una cella.

## Come misurare una finestra

```python
circ = costruisci(percorso, cc=cc)
circ.conta_data_ricevuto = lambda: None      # nessun SENDME
```

Sostituire un metodo con una funzione vuota è un trucco da laboratorio, non da produzione,
ed è il modo più diretto per rispondere a una domanda che altrimenti resterebbe teorica:
**quante celle manda l'exit prima di fermarsi?**

Nella configurazione storica illustrata, la misura era 124 con il controllo della congestione e 500 senza: i valori dipendono dai parametri e da quale finestra si esaurisce per prima. Il numero 500 sorprende
chi si aspetta 1000: è la finestra di *stream* a fermare il flusso, non quella di circuito.

## Che cosa serve sapere per farlo funzionare

- Serve un **server sulla porta 8080**, ed è la stessa porta che usa `make verifica-lab`:
  se lasci acceso il tuo, la suite si ferma dicendolo.
- Il file di prova dev'essere abbastanza grande da superare la finestra: con meno di 124
  celle (~60 KB) non si vede nulla di interessante.
- Gli StreamID devono essere **diversi** per ogni stream dello stesso circuito, e diversi da
  zero.
- Se il download si interrompe con `DESTROY`, verificare anche il contatore dei `SENDME` per circuito, ma controllare log, reason code ed eventuali altre cause prima di trarre conclusioni.

## Da dove vengono queste regole

| Nel codice | Nella specifica |
|---|---|
| `BEGIN`, `CONNECTED`, formato di ADDRPORT | tor-spec, *Opening streams and transmitting data* |
| motivi di `END` | tor-spec, *Closing streams* |
| finestre e `SENDME` | tor-spec, *Flow control* |
| `SENDME` autenticati | proposta 289 |
| controllo della congestione, `sendme_inc` | proposta 324 |
