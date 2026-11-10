# Laboratorio 6 — Scaricare e verificare il consenso

| | |
|---|---|
| **Capitolo** | 12 — Il sistema delle directory |
| **Serve la rete?** | sì |
| **Prerequisiti** | Laboratori 1–5 |
| **Tempo** | 3 ore per scriverlo, 1 minuto per rieseguirlo |
| **File** | `labs/it/codice/torlab/directory.py` |

## Che cosa dimostra

**Limite di sicurezza da non confondere con la dimostrazione:** il verificatore confronta le firme RSA del consenso con certificati scaricati dallo stesso servizio di directory, ma **non** verifica tali certificati rispetto a chiavi di identità delle autorità preinstallate e fidate; non controlla la firma/certificazione incrociata dei certificati, la loro scadenza o la validità temporale del consenso. Quindi il numero di firme RSA coincidenti **non prova da solo** che il consenso provenga dalle autorità Tor autentiche. Il codice non è adatto a un bootstrap sicuro della rete pubblica.

Il laboratorio esamina la catena di fiducia del sistema di directory e dimostra alcuni controlli crittografici su una rete privata: firme RSA del consenso, impronte SHA-256 dei microdescrittori e chiavi ntor. Il client didattico non completa però la verifica delle autorità fidate, come precisato sopra.

E, cosa più utile ancora, dimostra che la verifica **fallisce** quando deve: basta cambiare il valore di una banda nella parte firmata del consenso.

## Preparazione

Eseguire la dimostrazione **solo sulla rete privata Tor/Chutney** già preparata nei laboratori precedenti. Il nodo `000a` è specifico di tale rete; l'esempio non scarica o autentica un consenso della rete Tor pubblica.

```bash
make -C labs/it/laboratorio avvia
export PYTHONPATH=labs/it/codice
```

## Esecuzione

```bash
python3 - <<'EOF'
import base64
from torlab.circuito import costruisci
from torlab.laboratorio import relay
from torlab.directory import *

# un circuito di UN solo salto verso l'autorità, senza controllo della congestione:
# è quello che fa tor per le richieste di directory
circ = costruisci([relay("000a")], cc=False)
testo = scarica(circ, "/tor/status-vote/current/consensus-microdesc", 1).decode()
c = analizza_consenso(testo)
print(f"consenso: {len(testo)} byte; {' '.join(c.intestazione['valid-after'])}"
      f" -> {' '.join(c.intestazione['fresh-until'])}")

cert = analizza_certificati(scarica(circ, "/tor/keys/all", 3).decode())
print(f"metodo {c.intestazione['consensus-method'][0]}; firme {len(c.firme)}; certificati {len(cert)}")
for r in c.relay[:2]:
    print(f"  {r.nome} {r.ip}:{r.orport} w={r.banda} flag={sorted(r.flag)[:4]}...")

valide, richieste, _ = verifica_consenso(c, cert, 3)
assert valide >= richieste, "firme dei certificati forniti insufficienti"
print(f"firme valide: {valide} (richieste: {richieste})")

# il controllo negativo: una sola cifra cambiata. Si altera una banda qualunque del
# consenso vivo: nella rete di prova le bande sono misurate e cambiano, quindi fissarne
# il valore (per es. "Bandwidth=4096") renderebbe la replace un no-op quando quel valore
# non c'e', e la verifica sembrerebbe non fallire mai.
import re
banda = re.search(r"Bandwidth=(\d+)", testo)
assert banda is not None, "nessun campo Bandwidth trovato"
testo_alterato = testo.replace(banda.group(0), f"Bandwidth={int(banda.group(1)) + 1}", 1)
assert testo_alterato != testo
alterato = analizza_consenso(testo_alterato)
valide_alterato = verifica_consenso(alterato, cert, 3)[0]
assert valide_alterato == 0, "controllo negativo non riuscito"
print("consenso alterato -> firme valide:", valide_alterato)

dig = "-".join(base64.b64encode(r.microdesc).decode().rstrip("=") for r in c.relay)
md = analizza_microdescrittori(scarica(circ, f"/tor/micro/d/{dig}", 5).decode())
assert all(r.microdesc in md for r in c.relay), "mancano microdescrittori richiesti"
print(f"microdescrittori: {len(md)}; corrispondono agli m del consenso: "
      f"{all(r.microdesc in md for r in c.relay)}")
EOF
```

## Output atteso

Questo è un **output storico illustrativo**, non un risultato appena riprodotto. Date, nomi, conteggi delle firme e delle celle possono cambiare. La maggioranza di firme corrispondenti ai certificati forniti non equivale alla validazione della loro identità fidata. I campi `valid-after` e `fresh-until` indicano il periodo di *freschezza*, mentre `valid-until` indica separatamente la scadenza.

```
consenso: 5961 byte; 2026-09-24 16:01:20 -> 2026-09-24 16:01:40
metodo 36; firme 3; certificati 3
  test000a 127.0.0.1:5100 w=20 flag=['Authority', 'Fast', 'Guard', 'HSDir']...
  test005r 127.0.0.1:5105 w=4096 flag=['Fast', 'Guard', 'HSDir', 'Running']...
firme valide: 3 (richieste: 2)
consenso alterato -> firme valide: 0
microdescrittori: 8; corrispondono agli m del consenso: True
```

Come leggerlo:

- La rete privata ha intervalli di voto brevi. `valid-after` → `fresh-until` misura la *freschezza*, mentre `valid-after` → `valid-until` delimita la validità. L'output storico non fissa una durata universale di 40 secondi.
- **3 firme su 3 autorità, ne bastavano 2**: la regola è più della metà.
- **`firme valide: 0`** sul consenso alterato è la riga più importante della pagina. Una
  verifica che non fallisce mai non verifica nulla.
- L'impronta SHA-256 di ogni microdescrittore scaricato coincide con la riga `m` del consenso: viene dimostrato il **collegamento tramite hash**, ma non la completa autenticazione dei certificati delle autorità.

## Il dettaglio che fa inciampare

La firma non copre tutto il documento: si ferma subito dopo `directory-signature `. E
sui file scaricati da **CollecTor** c'è una riga di annotazione in testa,
`@type network-status-microdesc-consensus-3 1.0`, che **non fa parte** del documento
firmato.

Includendola, il digest cambia e *tutte* le firme risultano non valide, con un errore
che sembra crittografico ed è invece di formato. Mi è costato un'ora prima di capirlo.
`testo_firmato` parte perciò da `network-status-version`, e c'è un test che lo fissa.

## Verifica offline con i documenti disponibili nella repository

I percorsi `labs/it/dati/collector/consensus-microdesc-2026-09-23-15` e `labs/it/dati/collector/certs` citati nella precedente versione **non esistono nella repository**. È invece disponibile una coppia di file firmati della rete privata in `labs/it/codice/torlab/test/dati/`, usata da `test_directory.py`:

```python
from pathlib import Path
from torlab.directory import analizza_consenso, analizza_certificati, verifica_consenso

base = Path("labs/it/codice/torlab/test/dati")
consenso = analizza_consenso((base / "consenso-microdesc.txt").read_text())
certificati = analizza_certificati((base / "certificati-autorita.txt").read_text())
valide, richieste, _ = verifica_consenso(consenso, certificati, 3)
assert (valide, richieste) == (3, 2)  # coerenza con i certificati forniti, non trust anchor
```

Per la verifica di un consenso pubblico storico bisogna procurarsi separatamente da CollecTor anche i **certificati delle autorità corrispondenti a quel periodo**. Senza quei certificati le nove firme del consenso pubblico non si possono verificare. Il [Laboratorio 15](Laboratorio-15-Metriche.md) illustra i materiali. I dati firmati delle fixture non vanno modificati: basta un carattere per invalidare le firme.

## Verifica automatica

Il verificatore italiano `lab6` è in `scripts/verify_labs.py` e lavora sulla rete privata; la prova offline del modulo `test_directory.py` usa i file disponibili nella repository. Nessuno dei due controlla gli anchor di fiducia delle autorità come un client Tor completo.

## Problemi noti

| Sintomo | Causa |
|---|---|
| `RELAY_END NOTDIRECTORY` o HTTP `503` | il primo segnala un relay senza servizio directory; il secondo è una risposta HTTP. Leggere il risultato effettivo prima di diagnosticare. |
| `firme valide: 0` su un consenso pubblico archiviato a parte | controllare i certificati storici corrispondenti, la riga `@type` e i confini del testo firmato; gli archivi pubblici vanno recuperati separatamente |
| HTTP `503` da un servizio directory | controllare lo stato HTTP; un relay senza servizio directory può invece restituire `END NOTDIRECTORY` |
| Il consenso ha meno relay del previsto | l'hai scaricato durante un cambio di consenso; riprova dopo mezzo minuto |

---

# Il codice, in dettaglio

`labs/it/codice/torlab/directory.py`, circa 230 righe. Fa quattro cose: scarica documenti attraverso
un circuito, li analizza, ne verifica le firme, e collega i microdescrittori al consenso.

## Scaricare attraverso un circuito

```python
def scarica(circ: Circuito, percorso: str, stream_id: int) -> bytes:
    """GET HTTP/1.0 sul servizio di directory dell'ultimo salto, via BEGIN_DIR."""
    s = Stream(circ, stream_id)
    circ.invia(MessaggioRelay(ComandoRelay.BEGIN_DIR, stream_id, b""))
    _, msg = s._prossimo()
    if msg.comando != ComandoRelay.CONNECTED:
        raise ErroreCircuito(f"BEGIN_DIR rifiutato: {msg.comando}")
    s.invia(f"GET {percorso} HTTP/1.0\r\n\r\n".encode())
    risposta = s.ricevi_tutto()
    intestazione, _, corpo = risposta.partition(b"\r\n\r\n")
    stato = intestazione.split(b"\r\n")[0]
    if b" 200 " not in stato:
        raise ErroreCircuito(f"{percorso}: {stato.decode()}")
    return corpo
```

`BEGIN_DIR` chiede il servizio di directory all'ultimo relay, non una connessione TCP esterna. La specifica impone un **corpo vuoto** al client e che il server ignori qualsiasi corpo ricevuto. In caso di successo il server invia `CONNECTED` con corpo vuoto e il client deve ignorare il corpo ricevuto. Un nodo senza servizio directory può rispondere con `END NOTDIRECTORY`, che non è un errore HTTP `503`.

Sopra lo stream si parla **HTTP/1.0 in chiaro**. Sembra un anacronismo ed è una scelta: il
documento è già firmato dalle autorità, quindi non serve un canale autenticato per
trasportarlo, e una richiesta senza `Host` è la cosa più semplice che un relay debba saper
interpretare.

```python
circ = costruisci([relay("000a")], cc=False)
```

Il circuito di **un solo salto**, senza controllo congestione, è una dimostrazione **non anonima** di richiesta pubblica directory. Tor ammette questa modalità, ma può utilizzare anche cache e nodi di fallback: non tutte le richieste di directory devono essere a un solo salto.

> La scorciatoia vale per il consenso, **non** per i descrittori degli onion service, dove
> l'anonimato di chi chiede conta e gli HSDir rifiutano i circuiti di un salto
> ([Laboratorio 8](Laboratorio-08-Onion.md)).

## Il formato netdoc

Questo è un parser didattico di documenti attesi: non è un validatore netdoc resistente a tutti gli input malformati. Blocchi PEM tronchi possono causare eccezioni.

```python
def items(testo: str) -> list[Item]:
    """Divide un documento nel formato "netdoc" in item (dir-spec, netdoc)."""
    uscita, righe, i = [], testo.split("\n"), 0
    while i < len(righe):
        riga = righe[i]
        i += 1
        if not riga:
            continue
        parola, *argomenti = riga.split(" ")
        oggetto = None
        if i < len(righe) and righe[i].startswith("-----BEGIN "):
            j = i
            while not righe[j].startswith("-----END "):
                j += 1
            oggetto = "\n".join(righe[i:j + 1]).encode()
            i = j + 1
        uscita.append(Item(parola, argomenti, oggetto))
    return uscita
```

Tutti i documenti di directory di Tor — consenso, voti, descrittori, microdescrittori,
certificati — usano lo stesso formato: una parola chiave, degli argomenti separati da spazi,
e facoltativamente un oggetto PEM sulle righe seguenti. Venti righe di codice bastano a
leggerli tutti, ed è il motivo per cui conviene scrivere `items` una volta e costruirci
sopra gli analizzatori specifici.

`analizza_consenso` poi è una macchina a stati banale: `r` apre un nuovo relay, `s`, `w`,
`p`, `m` ne riempiono i campi. La riga `r` porta nickname, identità, indirizzo e porta; la
`w` il peso di banda; la `m` l'impronta del microdescrittore.

## La firma, e il byte che fa sbagliare tutti

```python
def testo_firmato(testo: str) -> bytes:
    """Parte del consenso coperta dalle firme: da "network-status-version" fino allo
    spazio dopo "directory-signature" (dir-spec, "directory-signature").

    I file scaricati da CollecTor iniziano con una riga di annotazione "@type ...",
    che non fa parte del documento firmato e va scartata.
    """
    inizio = testo.index("network-status-version ")
    pos = testo.index("\ndirectory-signature ") + len("\ndirectory-signature ")
    return testo[inizio:pos].encode()
```

La firma **non copre tutto il documento**: copre tutto ciò che precede, *inclusa* la parola
chiave `directory-signature` e lo spazio che la segue. Un byte in più o in meno e il digest
cambia, con un errore che sembra crittografico ed è di formato.

È qui che si inciampa con i file di **CollecTor**, che antepongono ai documenti una riga di
annotazione:

```
@type network-status-microdesc-consensus-3 1.0
network-status-version 3 microdesc
```

Quella riga **non fa parte** del documento firmato. Includendola, tutte e nove le firme
risultano non valide insieme — ed è proprio quel «tutte insieme» il sintomo che indica un
problema di formato e non di crittografia. Se fosse un problema di chiavi, ne fallirebbe
una.

```python
def verifica_firma(consenso: Consenso, firma: Firma, cert: CertificatoAutorita) -> bool:
    """La firma è RSA PKCS#1 v1.5 del digest *senza* l'identificativo dell'algoritmo:
    ricaviamo il digest dalla firma e lo confrontiamo con quello calcolato."""
    h = hashlib.sha256 if firma.algoritmo == "sha256" else hashlib.sha1
    atteso = h(testo_firmato(consenso.testo)).digest()
    try:
        ricavato = cert.chiave_firma.recover_data_from_signature(
            firma.firma, padding.PKCS1v15(), None)
    except Exception:
        return False
    return ricavato == atteso
```

`recover_data_from_signature` con algoritmo `None` restituisce il digest **contenuto** nella
firma, senza pretendere che sia incapsulato in una struttura ASN.1 con l'identificatore
dell'algoritmo. È esattamente lo schema di Tor, ed è il motivo per cui una normale `verify()`
qui fallirebbe su firme perfettamente valide: cercherebbe una struttura che non c'è.

L'algoritmo si legge dalla firma stessa: i consensi recenti usano SHA-256, ma il formato
ammette ancora SHA-1 e il codice deve saper leggere entrambi finché la rete li produce.

Qui **non** serve un confronto a tempo costante: il digest atteso lo calcoliamo da un
documento pubblico e non c'è alcun segreto da proteggere dalle misure di tempo. Dove il
segreto c'è, come nell'`AUTH` di ntor-v3, usiamo `hmac.compare_digest`.

## Il collegamento dei digest e il limite di fiducia

La catena completa richiede **chiavi di identità delle autorità già considerate fidate**, certificati di firma verificati e non scaduti, controllo dei tempi e quorum di firme del consenso. Solo dopo questi controlli la riga `m` con SHA-256 autentica il microdescrittore che contiene la `ntor-onion-key`.

```text
chiavi autorità fidate → certificati verificati → consenso valido e firmato → SHA-256 m → microdescrittore → ntor-onion-key
```

Il modulo didattico `directory.py` verifica soltanto la corrispondenza di firme RSA e impronte rispetto a certificati forniti dall'esterno: **non realizza il primo tratto della catena**. Non va quindi descritto come una verifica completa del consenso, né usato per autenticare la rete pubblica.

## Il controllo negativo

Le asserzioni verificano che la modifica sia realmente avvenuta e che il verificatore RSA didattico rilevi la manomissione. Non dimostrano autenticazione dei certificati rispetto a una chiave di fiducia.

```python
import re
banda = re.search(r"Bandwidth=(\d+)", testo)
assert banda is not None
testo_alterato = testo.replace(banda.group(0), f"Bandwidth={int(banda.group(1)) + 1}", 1)
assert testo_alterato != testo
alterato = analizza_consenso(testo_alterato)
assert verifica_consenso(alterato, cert, 3)[0] == 0
```

Una verifica che non fallisce mai non verifica nulla. Cambiare una singola cifra e vedere
le firme valide scendere a zero è la riga più importante del laboratorio: senza, non
sapresti distinguere un verificatore corretto da uno che restituisce sempre `True`.

Un dettaglio che è già costato un controllo silenziosamente inutile: **non** si fissa il
valore da sostituire (`testo.replace("Bandwidth=4096", …)`). Nella rete di prova le bande
sono misurate e cambiano nel tempo; se quel valore non è nel consenso, la `replace` non
tocca nulla, le firme restano valide e il controllo negativo non prova più niente. Per
questo, questo esempio e il verificatore italiano `lab6` cercano dinamicamente una banda. Il separato test unitario su fixture fissa può invece sostituire il valore noto `Bandwidth=4096`.

## Che cosa serve sapere per farlo funzionare

- **Non tutti i relay sono directory cache**: uno senza servizio può rispondere con `END NOTDIRECTORY`, mentre una directory può restituire un errore HTTP come `503`. Nella rete privata usa un'autorità disponibile (`000a`, `001a`, `002a`).
- Nella rete privata il consenso vale **40 secondi** (due intervalli di voto da 20), contro
  le tre ore della rete pubblica. Se scarichi durante un cambio di consenso puoi vedere
  numeri incoerenti: riprova dopo mezzo minuto.
- Il consenso microdesc e quello completo sono **documenti diversi** con percorsi diversi;
  le firme si verificano allo stesso modo ma le righe dei relay no.
- Per i microdescrittori il percorso è `/tor/micro/d/<impronte separate da ->`, in base64
  senza il riempimento `=`.

## Da dove vengono queste regole

| Nel codice | Nella specifica |
|---|---|
| `BEGIN_DIR` | tor-spec, *Opening streams and transmitting data* |
| formato netdoc | dir-spec, *netdoc document meta-format* |
| che cosa copre la firma | dir-spec, *Signing documents* |
| certificati delle autorità | dir-spec, *Directory authority key certificates* |
| microdescrittori | dir-spec, *Computing microdescriptors* |
