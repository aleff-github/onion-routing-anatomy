# Laboratorio 4 — Cifratura a strati e circuito di tre salti

| | |
|---|---|
| **Capitolo** | 10 — La cifratura a strati |
| **Serve la rete?** | sì |
| **Prerequisiti** | Laboratori 1–3 |
| **Tempo** | 3 ore per scriverlo, 1 minuto per rieseguirlo |
| **File** | `labs/it/codice/torlab/cifratura.py`, `labs/it/codice/torlab/circuito.py` |

## Che cosa dimostra

Come funziona davvero la «cipolla»: una chiave e un digest progressivo **per ogni salto
e per ogni direzione**, e un client che avvolge ogni messaggio in tanti strati quanti
sono i salti. Il relay intermedio non ha modo di sapere se ciò che gli arriva è un
messaggio per lui o uno strato da togliere: prova a riconoscerlo e, se non riesce,
inoltra.

E soprattutto: l'estensione di un circuito reale, un salto alla volta, fino all'exit.

## Preparazione

```bash
make -C labs/it/laboratorio avvia
export PYTHONPATH=labs/it/codice
```

## Esecuzione

```bash
python3 - <<'EOF'
import time
from torlab.celle import Comando
from torlab.circuito import costruisci
from torlab.laboratorio import relay

circ = costruisci([relay("003r"), relay("004r"), relay("006e")])
print("salti:", len(circ.cripto.salti), "| estensioni chieste all'exit:", circ.estensioni_exit)

# il padding di collegamento, che nel Laboratorio 1 non compariva
circ.canale.sock.settimeout(12)
visti, t = 0, time.time()
try:
    while time.time() - t < 12:
        if circ.canale.ricevi().comando == Comando.PADDING:
            visti += 1
except TimeoutError:
    pass
print(f"celle PADDING ricevute in 12 s: {visti}")
EOF
```

## Output atteso

```
salti: 3 | estensioni chieste all'exit: [(2, b'\x1f')]
celle PADDING ricevute in 12 s: 3
```

Come leggerlo:

- `costruisci` apre il canale verso il guard, crea il primo salto con ntor-v3 e poi
  estende due volte. Il messaggio `EXTEND2` ha **StreamID zero** (è un messaggio di
  controllo) e viaggia dentro una cella `RELAY_EARLY`, non `RELAY`: è quel dettaglio che
  prevede un budget massimo di otto celle `RELAY_EARLY` per circuito, non necessariamente otto salti
  ([Laboratorio 17](Laboratorio-17-Relay-early.md)).
- In questo esempio il controllo della congestione si chiede **solo all'ultimo salto**:
  `[(2, b'\x1f')]` è la risposta dell'exit, `sendme_inc` = 31.
- **Il padding di collegamento dipende dalla configurazione e dai tempi.** Estendere il circuito oltre il guard può rendere il canale idoneo al padding; la sua presenza nei dodici secondi di osservazione e il numero di celle non sono garantiti.

Il numero di celle `PADDING` mostrato è un esempio storico, non un risultato garantito; anche zero è possibile.

## Il cuore del laboratorio

Due cicli, e niente di più:

```python
def cifra(self, msg: MessaggioRelay, destinazione: int | None = None) -> bytes:
    d = len(self.salti) - 1 if destinazione is None else destinazione
    corpo = self.salti[d].avanti.firma(codifica_relay(msg))
    for i in range(d, -1, -1):
        corpo = self.salti[i].avanti.applica(corpo)
    return corpo

def decifra(self, corpo: bytes) -> tuple[int, MessaggioRelay]:
    for i, salto in enumerate(self.salti):
        corpo = salto.indietro.applica(corpo)
        if salto.indietro.riconosce(corpo):
            return i, decodifica_relay(corpo)
    raise ErroreCella("cella non riconosciuta da nessun salto: circuito da chiudere")
```

`riconosce` è più delicato di quanto sembri: verifica che il campo `Recognized` sia zero
**e** che il digest progressivo torni. Se il digest non torna, lo stato del digest non
va aggiornato, altrimenti un falso positivo desincronizzerebbe il circuito per sempre.
Per questo il codice lavora su una copia (`self.digest.copy()`) e la adotta solo se il
confronto riesce.

## Il limite dei test in memoria

`test_cifratura.py` costruisce un circuito simulato di tre relay e verifica che ogni
salto riconosca solo le proprie celle, che i relay intermedi vedano byte
indistinguibili dal caso, che una modifica venga rilevata a destinazione, e dimostra la
malleabilità di AES-CTR.

Ma quei test hanno un limite serio: client e relay simulati usano **lo stesso codice**.
Sbagliando, per esempio, l'ordine in cui si aggiorna il digest, lo si sbaglierebbe in
modo identico dalle due parti e i test passerebbero lo stesso. La verifica di interoperabilità più convincente consiste nel parlare con l'implementazione indipendente `tor` su una rete privata: il laboratorio è progettato per questa prova.

## Verifica automatica

Il controllo italiano `lab4` in `scripts/verify_labs.py` verifica la costruzione dei tre salti e osserva il padding, che può tuttavia mancare per casualità o configurazione. Il controllo `lab4` richiede la rete privata avviata; i test offline `test_cifratura.py` girano anche senza rete.

## Problemi noti

| Sintomo | Causa |
|---|---|
| `cella non riconosciuta da nessun salto: circuito da chiudere` | il digest si è desincronizzato: quasi sempre si sta aggiornando lo stato anche quando il riconoscimento fallisce |
| `celle PADDING ricevute in 12 s: 0` | il padding è casuale: capita. Se succede sempre, controlla che il circuito sia davvero di tre salti |
| L'estensione fallisce con `DESTROY` | controllare il motivo e i log: le identità non corrispondenti sono una possibile causa, ma Ed25519 non è sempre obbligatoria nei link specifier di `EXTEND2` |

---

# Il codice, in dettaglio

Due moduli: `labs/it/codice/torlab/cifratura.py` (la cipolla vera e propria, ~115 righe) e
`labs/it/codice/torlab/circuito.py` (canale, CircID e salti tenuti insieme, ~115 righe).

## Che cosa tiene una `Direzione`

```python
POS_DIGEST = slice(5, 9)
POS_RECOGNIZED = slice(1, 3)

def _aes_ctr(chiave):
    return Cipher(algorithms.AES(chiave), modes.CTR(bytes(16))).encryptor()

def _senza_digest(corpo):
    return corpo[:5] + bytes(4) + corpo[9:]
```

**L'IV è a zero**, e non è una scorciatoia: in Tor il contatore CTR prosegue di cella in
cella per tutta la vita del circuito, quindi il flusso di chiave non si ripete mai e non
serve un IV per salto. Reinizializzare il cifrario a ogni cella riprodurrebbe lo stesso
flusso e distruggerebbe la cifratura: è l'errore più grave che si possa fare in questo
modulo, e non produce alcun sintomo visibile finché qualcuno non guarda il traffico.

```python
@dataclass
class Direzione:
    cifrario: object
    digest: "hashlib._Hash"
```

Una `Direzione` tiene insieme due stati che devono avanzare **insieme**: il cifrario
AES-CTR e il digest progressivo. Sono due cose distinte nella specifica ma un'unica cosa
nella pratica, perché disallineare l'una dall'altra rompe il circuito in modo non
recuperabile. Ogni salto ne ha due (avanti e indietro), quindi un circuito di tre salti ha
sei `Direzione`.

## Cifrare e decifrare sono la stessa operazione

```python
def applica(self, dati):
    return self.cifrario.update(dati)
```

In modalità CTR cifrare e decifrare coincidono: entrambe sono uno XOR con il flusso di
chiave. Non è un'astuzia nostra — è la ragione per cui un relay intermedio può «togliere uno
strato» senza sapere se sta cifrando o decifrando, e senza distinguere il traffico in
andata da quello in ritorno.

È anche il motivo per cui AES-CTR è **malleabile**: cambiando un bit del testo cifrato si
cambia lo stesso bit del testo in chiaro. Il digest esiste proprio per accorgersene
(l'appendice B del libro lo mostra in pratica).

## Il digest non è della cella

```python
def firma(self, corpo):
    self.digest.update(_senza_digest(corpo))
    return corpo[:5] + self.digest.digest()[:4] + corpo[9:]
```

Il digest è dei **messaggi RELAY originati da questo salto o diretti a esso** in quella direzione, non delle celle inoltrate ad altri salti né di una sola cella. `update` accumula, e ogni cella dipende da tutte le precedenti.

Da qui la sequenza, che la specifica prescrive alla lettera: si azzera il campo Digest
(`_senza_digest`), si aggiorna lo stato dell'hash su quella versione azzerata, si prendono
i primi 4 byte del risultato e li si scrive nel campo. Chi riceve rifà lo stesso calcolo e
deve ottenere lo stesso valore.

Conseguenza pratica: **una sola cella persa o fuori ordine desincronizza il circuito per
sempre**. Non c'è modo di risincronizzarsi, e infatti Tor non ci prova: chiude il circuito.

Per i circuiti ordinari la funzione è SHA-1, per quelli verso un onion service SHA3-256.
SHA-1 qui non è una svista rimasta indietro: non serve resistenza alle collisioni, perché
l'avversario dovrebbe produrre una collisione su uno stato che non conosce e che cambia a
ogni cella.

## Il riconoscimento, e la copia che salva il circuito

```python
def riconosce(self, corpo):
    if corpo[POS_RECOGNIZED] != b"\x00\x00":
        return False
    prova = self.digest.copy()
    prova.update(_senza_digest(corpo))
    if prova.digest()[:4] != corpo[POS_DIGEST]:
        return False                 # falso positivo: stato invariato
    self.digest = prova
    return True
```

Questo è il punto più sottile dell'intero modulo.

Il primo filtro è il campo `Recognized`: se non è zero, la cella non è per noi e non si
tocca nulla. Scarta quasi tutto a costo zero.

Ma `Recognized` a zero **può capitare per caso**: sono due byte, succede all'incirca una
volta su 65 536. In quel caso il digest non tornerà. Se però avessimo aggiornato lo stato
per verificarlo, quel falso positivo avrebbe corrotto il digest per **tutte** le celle
successive.

Lavorare su una `copy()` e adottarla solo a verifica riuscita è ciò che rende il
riconoscimento un'operazione **senza effetti collaterali quando fallisce**. È esattamente
ciò che fa tor, e chi scrive questo modulo da sé lo scopre di solito dopo un circuito che
muore dopo qualche migliaio di celle senza ragione apparente.

## I due cicli della cipolla

```python
def cifra(self, msg: MessaggioRelay, destinazione: int | None = None) -> bytes:
    d = len(self.salti) - 1 if destinazione is None else destinazione
    corpo = self.salti[d].avanti.firma(codifica_relay(msg))
    for i in range(d, -1, -1):
        corpo = self.salti[i].avanti.applica(corpo)
    return corpo

def decifra(self, corpo: bytes) -> tuple[int, MessaggioRelay]:
    for i, salto in enumerate(self.salti):
        corpo = salto.indietro.applica(corpo)
        if salto.indietro.riconosce(corpo):
            return i, decodifica_relay(corpo)
    raise ErroreCella("cella non riconosciuta da nessun salto: circuito da chiudere")
```

In uscita: si firma con il digest del salto **di destinazione**, poi si avvolge dall'interno
verso l'esterno. In entrata: si toglie uno strato alla volta dall'esterno verso l'interno, e
dopo ciascuno si prova a riconoscere.

Nota che `decifra` **non sa** da quale salto arriva la cella: lo scopre. È la stessa
situazione del relay intermedio, che toglie il proprio strato e inoltra senza sapere se il
risultato è leggibile da qualcuno.

## Estendere un circuito

```python
def estendi(self, r: InfoRelay, estensioni=()) -> list[tuple[int, bytes]]:
    st, hd = ntor3_client_inizio(r.id_ed, r.ntor, codifica_estensioni(list(estensioni)))
    corpo = corpo_extend2("127.0.0.1", r.porta, r.id_rsa, r.id_ed, HTYPE_NTOR_V3, hd)
    self.invia(MessaggioRelay(ComandoRelay.EXTEND2, 0, corpo), early=True)
    salto, msg = self.ricevi()
    if msg.comando != ComandoRelay.EXTENDED2:
        raise ErroreCircuito(f"estensione fallita: {ComandoRelay(msg.comando).name}")
    sm, k = ntor3_client_fine(st, hdata_created2(msg.dati))
    self.cripto.salti.append(Salto.da_chiavi(ChiaviCircuito.da_flusso(k)))
    return decodifica_estensioni(sm)
```

Questo estratto riproduce il metodo reale `Circuito.estendi`; i tipi, le dipendenze e le costanti sono definiti nel modulo completo.

Tre dettagli che, sbagliati, fanno fallire l'estensione in modi poco chiari:

- **StreamID zero**: `EXTEND2` è un messaggio di controllo del circuito, non di uno stream.
- **`RELAY_EARLY`, non `RELAY`**: è il tipo di cella che il protocollo richiede per le
  estensioni, ed è quello che limita a otto i salti di un circuito
  ([Laboratorio 17](Laboratorio-17-Relay-early.md)).
- **Identità del relay**: l'esempio usa specificatori RSA ed Ed25519. La specifica non rende Ed25519 sempre obbligatoria in `EXTEND2`; il relay che estende DOVREBBE verificare l'identità Ed25519 quando la conosce dal consenso. La sua assenza non determina necessariamente `DESTROY`.

In questo esempio il controllo della congestione si chiede **solo all'ultimo salto**: l'estensione
`(1, b"")` va all'exit e non ai middle.

## Il limite dei test in memoria

`test_cifratura.py` costruisce un circuito simulato di tre relay e verifica che ogni salto
riconosca solo le proprie celle, che gli intermedi vedano byte indistinguibili dal caso, che
una modifica venga rilevata a destinazione, e dimostra la malleabilità di AES-CTR.

Quei test hanno però un limite serio, che vale la pena tenere a mente ogni volta che si
scrive un test di un protocollo: **client e relay simulati usano lo stesso codice**.
Sbagliando l'ordine in cui si aggiorna il digest, lo si sbaglierebbe in modo identico dalle
due parti e i test passerebbero lo stesso. La verifica più convincente è l'interoperabilità con `tor` sulla rete privata.

## Che cosa serve sapere per farlo funzionare

- Le chiavi del circuito arrivano dal flusso di ntor: 20+20 byte di digest (`Df`, `Db`) e
  16+16 di chiave (`Kf`, `Kb`), in tutto 72. L'ordine conta e non è indovinabile.
- Il **seme del digest** di una direzione è `Df` o `Db`, non una stringa vuota.
- Una `Direzione` non si può riusare per due circuiti: porta con sé un contatore CTR.
- Se ottieni `cella non riconosciuta da nessun salto: circuito da chiudere` su una cella che dovrebbe essere tua, nel 90 % dei
  casi hai aggiornato il digest in un ramo in cui non dovevi.

## Da dove vengono queste regole

| Nel codice | Nella specifica |
|---|---|
| campi Recognized e Digest | tor-spec, *Relay cells* |
| calcolo del digest | tor-spec, *Calculating the 'Digest' field* |
| come un relay instrada | tor-spec, *Routing relay cells* |
| chiavi del circuito | tor-spec, *Setting circuit keys* |
| EXTEND2 e specificatori | tor-spec, *Creating circuits* |
