# Laboratorio 8 — Trovare e leggere il descrittore di un onion service

| | |
|---|---|
| **Capitolo** | 14 — Onion service |
| **Serve la rete?** | sì |
| **Prerequisiti** | Laboratori 1–6 |
| **Tempo** | 4 ore per scriverlo, 2 minuti per rieseguirlo |
| **File** | `labs/it/codice/torlab/onion.py` |

## Che cosa dimostra

**Ambito reale dell'esempio:** il chiamante sceglie esplicitamente il relay finale `006e`. `scarica_descrittore()` **non calcola né sceglie un HSDir responsabile**: la funzione `hsdir_responsabili()` per l'anello è separata e non viene invocata nell'esperimento. Il recupero del descrittore tramite tre salti non costituisce una verifica dell'algoritmo di posizionamento sull'anello. Il client didattico inoltre non supporta i cookie e le credenziali della scoperta ristretta.

L'indirizzo `.onion` codifica la chiave pubblica Ed25519, il checksum e la versione. Chi conosce già l'indirizzo può calcolare le chiavi accecate dei periodi: l'accecamento non nasconde la corrispondenza a un osservatore che conosce quell'indirizzo.

Che un indirizzo `.onion` **è** una chiave pubblica, e che da quella chiave si può
calcolare tutto il resto: la chiave accecata del periodo corrente, la posizione del
descrittore sull'anello degli HSDir, e infine il descrittore stesso, di cui si verifica
la firma e si decifrano i due strati fino ai punti di introduzione.

La chiave accecata è il meccanismo che impedisce a un HSDir di sapere quale servizio sta
ospitando: cambia a ogni periodo, e solo chi conosce l'indirizzo può collegarla al
servizio.

## Preparazione

```bash
make -C labs/it/laboratorio avvia
export PYTHONPATH=labs/it/codice
```

L'onion service della rete privata è il nodo `009h`; il suo indirizzo è in
`labs/it/laboratorio/net/nodes/009h/hidden_service/hostname`.

## Esecuzione

```bash
python3 - <<'EOF'
import calendar, time
from torlab.circuito import costruisci, ErroreCircuito
from torlab.laboratorio import relay, NODI
from torlab.directory import analizza_consenso, scarica
from torlab.onion import *

indirizzo = (NODI / "009h/hidden_service/hostname").read_text().strip()
print("indirizzo:", indirizzo)
A = chiave_da_indirizzo(indirizzo)
print("ricostruito dall'indirizzo:", indirizzo_onion(A) == indirizzo)

c = analizza_consenso(scarica(costruisci([relay("000a")], cc=False),
                              "/tor/status-vote/current/consensus-microdesc", 1).decode())
ts = lambda k: calendar.timegm(time.strptime(" ".join(c.intestazione[k]), "%Y-%m-%d %H:%M:%S"))
t = tempo(ts("valid-after"), ts("fresh-until") - ts("valid-after"), rete_di_test=True)
print("periodo:", t.periodo, "durata (min):", t.durata_minuti)
Ap = chiave_accecata(A, t.periodo, t.durata_minuti)
print("chiave accecata:", Ap.hex()[:8] + "...")

# 1. il controllo negativo: un salto solo
try:
    scarica_descrittore(Ap, [relay("006e")])
    raise AssertionError("richiesta a un salto riuscita inaspettatamente")
except ErroreCircuito as e:
    print("con un circuito di un salto ->", e)

# 2. tre salti, come un client vero
desc = analizza_descrittore(
    scarica_descrittore(Ap, [relay("003r"), relay("004r"), relay("006e")]), A, Ap)
print(f"lifetime {desc.durata_minuti} revisione {desc.revisione} "
      f"punti di introduzione {len(desc.punti_di_introduzione)}")
for riga in desc.strato_interno.splitlines()[:6]:
    print("  ", riga[:66])
EOF
```

## Output atteso

**Output dell'esecuzione di riferimento, a titolo illustrativo.** Indirizzo, chiave accecata, intervallo, revisione e testo dell'errore HTTP possono cambiare a seconda della rete e di Tor. Il codice controlla un rifiuto del circuito a un salto, ma la specifica non impone universalmente la stessa stringa `HTTP 503` in ogni configurazione.

```
indirizzo: jnl3qwwgchhbkammkqajwyuvcnt3shvaio53lnui7zr735hx4ab2slyd.onion
ricostruito dall'indirizzo: True
periodo: 3729719 durata (min): 8
chiave accecata: 9fac5013...
con un circuito di un salto -> /tor/hs/3/n6xQEzASD31484ta7ZKChxNX14NTqcIyQlwXma5N9K0: HTTP/1.0 503 Rejecting single hop HS v3 descriptor request
lifetime 180 revisione 14695413 punti di introduzione 3
   create2-formats 2
   flow-control 1-2 31
   introduction-point AwAGfwAAARPvAhR4dPChvz+XuVSBXw7KiSkEsfo42wMgeF0
   onion-key ntor b0otE3LtQn7qnrGr8SKXxHCTOG9HSomwsQornrxIOCs=
   auth-key
   -----BEGIN ED25519 CERT-----
```

Indirizzo, revisione e chiavi saranno diversi dai tuoi: cambiano a ogni rigenerazione
della rete.

Come leggerlo:

- `indirizzo_onion(chiave_da_indirizzo(x)) == x` dimostra che l'indirizzo non è un
  identificatore assegnato da qualcuno: è la chiave pubblica più un checksum e un byte di
  versione, in base32. 56 caratteri.
- **`durata (min): 8`**: nella rete di laboratorio il periodo dura otto minuti invece di
  24 ore. Il modulo didattico in modalità test ricava la durata dall'intervallo dei voti, non legge direttamente `hsdir_interval`. Senza questa scorciatoia un laboratorio sui
  periodi sarebbe impraticabile.
- **`flow-control 1-2 31`**: il servizio dichiara di supportare il controllo della
  congestione, con lo stesso `sendme_inc` = 31 visto nel
  [Laboratorio 5](Laboratorio-05-Stream.md).
- **Tre punti di introduzione**, il valore predefinito.

## Come ho trovato l'errore (metodo, non aneddoto)

La prima esecuzione non trovava il descrittore su **nessuno** degli otto HSDir. Poiché
li avevo provati tutti, la scelta dell'HSDir non poteva essere la causa: restavano la
chiave accecata o la richiesta.

Per separare le due ipotesi ho chiesto al client vero della rete di scaricare lo stesso
descrittore, dalla porta di controllo (`HSFETCH`, poi
`GETINFO hs/client/desc/id/...`), e ho letto nel suo certificato la chiave accecata che
il servizio stava davvero usando: coincideva con la mia. Quindi il problema era la
richiesta — e infatti il codice di tor rifiuta le richieste di descrittori HS da circuiti
di un solo salto. Con tre salti è arrivato.

Vale in generale: quando un esperimento fallisce, si cerca un punto intermedio in cui
confrontare il proprio risultato con quello di un'implementazione di riferimento.

## Un limite onesto di questo laboratorio

Nella rete privata gli HSDir sono otto e il servizio carica il descrittore su
2 × 4 = 8 di essi, cioè su **tutti**. Trovare il descrittore quindi non dimostra che il
calcolo dell'anello sia giusto. Il log del client (`info.log`) registra a quale HSDir si
è rivolto, ed è uno dei tre che il nostro codice indicherebbe per quella replica in quel
momento: coerente, ma una sola osservazione non è una prova. L'esercizio 14.x del libro
propone una verifica più solida.

## Verifica automatica

Il verificatore italiano `lab8` richiede una rete privata Tor attiva; `labs/it/codice/torlab/test/test_onion.py` esegue test offline su vettori di indirizzi, checksum, descrittore firmato conservato e periodo errato. I due tipi di prova non sono equivalenti.

Il controllo `lab8` verifica l'indirizzo, il rifiuto a un salto e la decifratura del
descrittore con almeno un punto di introduzione.

## Problemi noti

Una cartella `authorized_clients/` semplicemente vuota **non abilita di per sé** la scoperta ristretta, né implica sempre un errore `400`. Quando l'autorizzazione è realmente abilitata devono essere presenti file client validi e almeno una voce `auth-client` nel descrittore; occorre controllare i log e la configurazione effettiva.

| Sintomo | Causa |
|---|---|
| `503 Rejecting single hop HS v3 descriptor request` | è il controllo negativo: con tre salti funziona |
| `404` da tutti gli HSDir | il servizio non ha ancora pubblicato (attendi), oppure la chiave accecata è calcolata per il periodo sbagliato |
| `400 Invalid HS descriptor` nei log del servizio | controllare la configurazione e i documenti effettivamente generati; una cartella `authorized_clients` vuota non è di per sé una diagnosi sufficiente. Vedi [Laboratorio 13](Laboratorio-13-Scoperta-ristretta.md) |

---

# Il codice, in dettaglio

`labs/it/codice/torlab/onion.py`, circa 250 righe. È il modulo più denso del repository: contiene
aritmetica di curva ellittica, un calendario, un anello distribuito e due strati di
cifratura.

## L'indirizzo è la chiave

```python
def indirizzo_onion(chiave: bytes) -> str:
    """base32(PUBKEY | CHECKSUM | VERSION) + ".onion" (rend-spec, ONIONADDRESS)."""
    checksum = hashlib.sha3_256(b".onion checksum" + chiave + bytes([VERSIONE])).digest()[:2]
    return base64.b32encode(chiave + checksum + bytes([VERSIONE])).decode().lower() + ".onion"
```

Un indirizzo `.onion` v3 è: 32 byte di chiave pubblica Ed25519, 2 byte di checksum, 1 byte
di versione, il tutto in base32 minuscolo. 35 byte → 56 caratteri.

Non c'è nessun registro, nessuna autorità che assegna i nomi: **l'indirizzo è la chiave**.
È il motivo per cui non serve un sistema di certificati per gli onion service, e anche il
motivo per cui gli indirizzi sono impronunciabili.

Il checksum non protegge da un avversario — chiunque può ricalcolarlo — ma dagli errori di
trascrizione. La stringa `".onion checksum"` all'inizio è, ancora una volta, separazione di
dominio.

## Il fattore accecante

```python
def fattore_accecante(A: bytes, periodo: int, durata_minuti: int) -> int:
    n = b"key-blind" + struct.pack(">QQ", periodo, durata_minuti)
    h = bytearray(hashlib.sha3_256(b"Derive temporary signing key\x00" + A + BASE_STR + n).digest())
    h[0] &= 248                                    # "clamping" come per Ed25519
    h[31] &= 63
    h[31] |= 64
    return int.from_bytes(h, "little")


def chiave_accecata(A: bytes, periodo: int, durata_minuti: int) -> bytes:
    """A' = h·A: la chiave pubblica del servizio per un certo periodo."""
    return _codifica(_moltiplica(fattore_accecante(A, periodo, durata_minuti), _decodifica(A)))
```

Questo è il meccanismo che impedisce a un HSDir di sapere quale servizio sta ospitando.

Il *nonce* `N` contiene numero e durata del periodo, entrambi su 8 byte: **cambiando periodo
cambia N, quindi h, quindi la chiave**. Gli HSDir responsabili di ieri non riconoscono il
servizio di oggi, e nessuno può correlare le due cose senza conoscere l'indirizzo.

La stringa `"Derive temporary signing key"` termina con un byte zero — è l'`INT_1(0)` della
specifica — e separa questo calcolo da ogni altro che usi SHA3-256.

Le tre operazioni sulla riga `h[0] &= 248; h[31] &= 63; h[31] |= 64` sono il **clamping** di
Ed25519:

| Operazione | Effetto | Perché |
|---|---|---|
| `h[0] &= 248` | azzera i 3 bit bassi | rende lo scalare multiplo di 8, eliminando la componente di torsione del gruppo |
| `h[31] &= 63` | azzera il bit 255 | tiene lo scalare nell'intervallo previsto |
| `h[31] \|= 64` | forza il bit 254 | garantisce che sia abbastanza grande, contro attacchi sui bit alti |

Si copiano dalla specifica e si sbagliano appena si prova a ricordarle a memoria.
L'appendice B del libro spiega perché ciascuna serve.

**`int.from_bytes(h, "little")`**: little-endian, al contrario di quasi tutti i campi di
Tor, che sono big-endian. È la convenzione di Ed25519, non quella del protocollo. Un errore
qui produce una chiave accecata plausibile e sbagliata, e l'unico sintomo è che nessun HSDir
ha il descrittore: nessun messaggio d'errore, solo 404.

`_moltiplica` è una moltiplicazione scalare su curva. Le librerie crittografiche comuni non
la espongono — firmano e verificano, non fanno aritmetica — ed è il motivo per cui il modulo
contiene una trentina di righe di Ed25519 scritte a mano, tratte dalle formule della
RFC 8032. Sono lente e non protette dagli attacchi sui tempi: vanno benissimo qui e in
nessun altro posto.

## Il tempo

**Limite del modulo:** `tempo()` restituisce il numero di periodo e l'indicazione sulla scelta del SRV corrente o precedente, **non il valore SRV** ottenuto dal consenso. Nell'esempio non si calcola l'anello a partire dal SRV. La durata test è derivata dall'intervallo dei voti passato alla funzione e non dalla lettura diretta di `hsdir_interval` nel modulo; otto minuti è un valore della configurazione privata.

```python
t = tempo(valid_after, intervallo_voto, rete_di_test=True)
Ap = chiave_accecata(A, t.periodo, t.durata_minuti)
```

`tempo` replica il calcolo di tor a partire dal `valid-after` del consenso e dall'intervallo
di voto, e dice anche **quale SRV usare**: quello corrente o il precedente.

Periodi e SRV sono sfasati di mezza giornata, di proposito. Un client deve scegliere con
cura: nella mezza giornata fra l'inizio di un periodo e il successivo SRV usa quello
corrente, nell'altra metà il precedente. Sbagliare significa calcolare l'anello giusto nel
momento sbagliato.

Nella configurazione storica della rete privata il periodo dura **8 minuti** invece di 24 ore: la funzione `tempo(..., rete_di_test=True)` lo calcola a partire dall'intervallo di voto. Per verificare un'altra rete occorre confrontare questo risultato con i parametri e le regole effettivamente adottati dal relativo client Tor.

## Scaricare e decifrare

**Separazione tra anello e download:** `hsdir_responsabili()` calcola potenziali HSDir a partire da chiavi Ed25519, SRV, periodo e parametri coerenti. `scarica_descrittore(accecata, percorso)` **non** la chiama: chiede `/tor/hs/3/<chiave-accecata-base64>` sul servizio directory dell'ultimo hop già indicato nel parametro `percorso` (nell'esempio `006e`).

**Scoperta ristretta non supportata da questo parser:** non usa la chiave x25519 dell'utente autorizzato per decifrare il `descriptor_cookie` ricevuto da `auth-client`. La decifratura del secondo strato mostrata vale per i servizi privi di restrizioni, non per i descrittori autorizzati del [Laboratorio 13](Laboratorio-13-Scoperta-ristretta.md).

**Controlli di sicurezza nel codice:** `analizza_descrittore()` verifica che il certificato di tipo 08 sia legato alla chiave accecata attesa e firmato da essa, controlla la firma del descrittore e i limiti di `descriptor-lifetime` (30--720 minuti). La scadenza del certificato si controlla con `check_expiration=True`, che un client con dati correnti deve usare; il valore predefinito è `False` perché i descrittori archiviati del laboratorio sono già scaduti. Il decodificatore non confronta il `revision-counter` con descrittori già in memoria: è compito del client. `chiave_da_indirizzo()` rifiuta con `ValueError` qualunque indirizzo che non sia di 56 caratteri Base32 con versione e checksum corretti.

```python
d = scarica_descrittore(Ap, [relay("003r"), relay("004r"), relay("006e")])
desc = analizza_descrittore(d, A, Ap)
```

`scarica_descrittore` **non calcola l'anello HSDir**: chiede `/tor/hs/3/<chiave accecata in base64 senza =>` su uno stream `BEGIN_DIR` verso il nodo finale esplicitamente passato dal chiamante.

**Serve un circuito di tre salti.** Un HSDir rifiuta le richieste che arrivano da un
circuito di un solo salto, con `503 Rejecting single hop HS v3 descriptor request`: se
accettasse, conoscerebbe l'indirizzo IP di chi cerca quel servizio. È una differenza
sostanziale rispetto al consenso ([Laboratorio 6](Laboratorio-06-Directory.md)), dove il
circuito di un salto va benissimo.

`analizza_descrittore` fa tre cose in fila, e l'ordine conta:

1. verifica che il certificato della chiave di firma sia emesso dalla **chiave accecata
   attesa** — cioè quella che abbiamo calcolato noi dall'indirizzo, non quella che il
   descrittore dichiara;
2. verifica la firma del descrittore;
3. decifra i due strati.

Saltare il primo passo significherebbe fidarsi di ciò che il descrittore dice di sé.

I due strati servono a scopi diversi: quello esterno è leggibile da chiunque conosca
l'indirizzo, quello interno solo dai client autorizzati quando la scoperta ristretta è
attiva ([Laboratorio 13](Laboratorio-13-Scoperta-ristretta.md)).

## Come ho trovato l'errore, e perché il metodo conta

La prima esecuzione non trovava il descrittore su **nessuno** degli otto HSDir. Poiché li
avevo provati tutti, la scelta dell'HSDir non poteva essere la causa: restavano la chiave
accecata o la richiesta.

Per separare le due ipotesi ho chiesto al client `tor` della rete di scaricare lo stesso
descrittore, dalla porta di controllo (`HSFETCH`, poi `GETINFO hs/client/desc/id/...`), e ho
letto nel suo certificato la chiave accecata che il servizio stava davvero usando:
coincideva con la mia. Quindi il problema era la richiesta — e il codice di tor ha mostrato
il perché.

Vale in generale: **quando un esperimento fallisce, si cerca un punto intermedio in cui
confrontare il proprio risultato con quello di un'implementazione di riferimento.** Il
client `tor` della rete di laboratorio è quel punto, e risponde a `GETINFO` su quasi tutto.

## Un limite onesto di questo laboratorio

Nella rete privata gli HSDir sono otto e il servizio carica il descrittore su 2 × 4 = 8 di
essi, cioè su **tutti**. Trovare il descrittore quindi non dimostra che il calcolo
dell'anello sia giusto: lo troveresti anche sbagliando.

Il log del client (`info.log`) registra a quale HSDir si è rivolto, ed è uno dei tre che il
nostro codice indicherebbe per quella replica in quel momento: coerente, ma una sola
osservazione non è una prova. Per una verifica seria servirebbe una rete con molti più
HSDir, oppure il confronto sistematico con `tor` su molti periodi.

## Che cosa serve sapere per farlo funzionare

- Il servizio dev'essere **partito e aver pubblicato**: dopo un riavvio della rete servono
  alcune decine di secondi.
- Se ottieni `404` da tutti gli HSDir, il sospetto numero uno è il **periodo**: prova a
  calcolare la chiave accecata anche per il periodo precedente e per il successivo.
- Se compare `400 Invalid HS descriptor`, controllare i dettagli del descrittore e dei file di autorizzazione nei log; **non attribuire automaticamente** l'errore a una cartella `authorized_clients` vuota ([Laboratorio 13](Laboratorio-13-Scoperta-ristretta.md)).
- L'indirizzo del servizio è in `labs/it/laboratorio/net/nodes/009h/hidden_service/hostname` e **cambia a
  ogni rigenerazione della rete**.

## Da dove vengono queste formule

| Nel codice | Nella specifica |
|---|---|
| formato dell'indirizzo | rend-spec, *Encoding onion addresses* |
| fattore accecante e clamping | rend-spec, *Appendix A: Signature scheme with key blinding* |
| periodi e SRV | rend-spec, *Publishing shared random values* |
| anello degli HSDir | rend-spec, *Generating and publishing hidden service descriptors* |
| strati del descrittore | rend-spec, *Hidden service descriptors: encryption format* |
