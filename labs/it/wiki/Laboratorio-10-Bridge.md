# Laboratorio 10 — Un bridge obfs4 e lo sguardo del censore

| | |
|---|---|
| **Capitolo** | 16 — Censura e pluggable transports |
| **Serve la rete?** | sì, ma **un'altra**: `libro-bridge` |
| **Prerequisiti** | Laboratorio 1 |
| **Tempo** | 1–2 ore |
| **File** | `scripts/verify_bridge_lab.py` |

## Che cosa dimostra

Confrontiamo **nella sola rete privata** un collegamento TLS a un normale ORPort con un collegamento obfs4. Nella cattura di riferimento il primo segmento TLS inizia per `16 03 01`, mentre il flusso obfs4 non presenta un'intestazione TLS riconoscibile. Si tratta di un'**osservazione su una cattura specifica**: non significa che ogni collegamento Tor inizi con quegli stessi byte, né che nessun analizzatore possa mai identificare obfs4 mediante altri segnali (IP, tempi, statistiche di traffico).

Il sondaggio con un normale `ClientHello` TLS non completa il trasporto obfs4: nella prova storica è scaduto il timeout senza ricevere una risposta utile. La specifica obfs4 prevede di scartare handshake non validi e raccomanda un ritardo casuale prima di chiudere la connessione; **non garantisce silenzio perpetuo**, né impedisce di bloccare un indirizzo già conosciuto. Questa attività dimostra soltanto un caso di resistenza al sondaggio attivo, non l'anonimato assoluto del bridge.

## Preparazione

**Attenzione allo stato della rete:** i target `pulisci` eliminano `labs/it/laboratorio/net/`, comprese le chiavi private e i log generati. Usarli **solo su una rete sacrificabile** e conservare altrove gli artefatti da preservare. Se l'immagine non è stata costruita, eseguire prima `make -C labs/it/laboratorio immagine`. Non avviare altre edizioni sullo stesso host: utilizzano le medesime porte.


Questo laboratorio usa una topologia diversa, con un'autorità dei bridge
(`003ba`), un bridge obfs4 (`009br`) e un client che lo usa (`011bc`).

```bash
make -C labs/it/laboratorio pulisci
make -C labs/it/laboratorio avvia RETE=libro-bridge
```

Alla fine, per tornare alla rete normale:

```bash
make -C labs/it/laboratorio pulisci
make -C labs/it/laboratorio avvia
```

È disponibile anche `make verifica-lab-bridge`, che scambia le due reti ed esegue **quattordici controlli propri** (vedi «Verifica automatica»). Va lanciata seguendo `docs/it/procedura-laboratori-dal-vivo.md`, dopo una copia di sicurezza di `labs/it/laboratorio/net/`.

Porte di questa rete: il client con bridge ha la **SocksPort 9011**, il bridge ascolta
obfs4 sulla **9909**.

## Passo 1: il client si collega attraverso il bridge

```bash
grep -E "new bridge descriptor|Only one bridge|Bootstrapped 100" labs/it/laboratorio/net/nodes/011bc/notice.log
```

```
[notice] new bridge descriptor 'test009br' (fresh): $DE539956E7E6A323...~test009br at 127.0.0.1
[warn] Only one bridge (transport: 'obfs4') is configured. You should have at least two
       for conflux, for any transport that is not 'snowflake'.
[notice] Bootstrapped 100% (done): Done
```

Il log mostra che il client ha ottenuto un descrittore del bridge configurato e ha completato il bootstrap. **Il log da solo non prova da quale canale sia stato scaricato il descrittore**: i bridge non sono elencati nel consenso pubblico, ma il client deve conoscerne preventivamente l'indirizzo e i parametri di trasporto. L'avviso segnala una limitazione di Conflux con un solo bridge obfs4 in questa configurazione, non un fallimento del bootstrap.

```bash
docker exec torlibro-rete curl -s -o /dev/null -w "%{http_code}\n" \
  --socks5-hostname 127.0.0.1:9011 http://127.0.0.1:8080/
```

```
200
```

(avviare prima, in un altro terminale, il server web **solo locale** e da una cartella vuota, così che non possa servire file del repository o chiavi dei nodi: `python3 -m http.server 8080 --bind 127.0.0.1 --directory "$(mktemp -d)"`; un HTTP 200 verifica la richiesta, non prova da solo la resistenza alla censura)

## Passo 2: che cosa vede il censore

Catturiamo dall'interno del container il traffico verso la porta obfs4 del bridge e
verso un ORPort normale, mentre il client usa il bridge e noi apriamo un canale con il
[Laboratorio 1](Laboratorio-01-Canale.md):

```bash
# Terminale A: server locale su 127.0.0.1:8080 già attivo.
# La cattura sovrascrive b1.pcap: salvarla prima se necessario.
docker exec -u 0 -d torlibro-rete sh -c \
  "timeout 25 tcpdump -i lo -w /lab/net/b1.pcap 'tcp port 9909 or tcp port 5104' >/dev/null 2>&1"
sleep 2
# Genera traffico obfs4, esclusivamente verso la rete privata:
docker exec torlibro-rete curl --silent --show-error --max-time 15 \
  --noproxy "" --socks5-hostname 127.0.0.1:9011 http://127.0.0.1:8080/
# Genera anche un collegamento TLS al relay locale, da un terminale host:
PYTHONPATH=labs/it/codice python3 - <<'PY'
from torlab.canale import apri_canale
from torlab.laboratorio import relay
r = relay("004r", client="010c")
apri_canale("127.0.0.1", r.porta, identita_attesa=r.id_ed)
PY
# Attendi la chiusura di tcpdump prima di leggere il file.
sleep 27
for p in 5104 9909; do
  echo "== porta $p, primo segmento con dati =="
  docker exec torlibro-rete tshark -r /lab/net/b1.pcap \
    -Y "tcp.dstport==$p && tcp.len>0" -T fields -e tcp.len -e tcp.payload | head -1
  echo "frame riconosciuti come TLS sulla porta $p:"
  docker exec torlibro-rete tshark -r /lab/net/b1.pcap \
    -Y "tls && tcp.port==$p" -T fields -e frame.number | wc -l
done
```

```
== porta 5104, primi byte dal client ==
1533   16030105f8010005f4030305cc9ad005e921614509b15f6151135f983b...
== porta 9909, primi byte dal client ==
602    f23abb4e8c3a45ab0e92958157c177bba1cc5dd27e80d74db45d77b425...

== pacchetti riconosciuti come TLS ==
porta 5104: 29
porta 9909: 0

== dimensioni dei segmenti obfs4 (client -> bridge) ==
602 1762 1308 1414 643 2183 2195 1568 1308 2037 616 1346
```

Come leggerlo:

- **`16 03 01`** è un prefisso compatibile con un record di handshake TLS (campo versione legacy `03 01`, **non** prova della versione TLS effettivamente negoziata). Nella prova storica il traffico verso
  la 5104 era riconosciuta come TLS nella cattura di riferimento: 29 frame classificati. Un censore ha da dove partire per
  cercare le caratteristiche specifiche di Tor — e comunque l'indirizzo di un relay
  pubblico sta nel consenso, che è pubblico per definizione.
- Verso la 9909 i primi byte non hanno struttura, **zero** pacchetti riconosciuti come
  TLS, e le dimensioni dei segmenti non riflettono affatto le celle da 514 byte. Il
  censore vede byte dall'aspetto casuale verso un indirizzo che **non ricava dal consenso pubblico**; se conosce già quell'indirizzo può comunque bloccarlo.
- I valori esatti (byte, conteggi, dimensioni) cambiano a ogni esecuzione; quello che non
  cambia è il contrasto.

## Passo 3: sondare il bridge

Un censore che sospetta un bridge prova a parlargli. Facciamolo, con il codice del
Laboratorio 1:

```bash
PYTHONPATH=labs/it/codice python3 - <<'PY'
import ssl
from torlab.canale import ErroreCanale, apri_canale
from torlab.laboratorio import relay
r = relay("004r", client="010c")
try:
    apri_canale("127.0.0.1", 9909, identita_attesa=r.id_ed)
    raise AssertionError("connessione TLS ordinaria inaspettatamente riuscita su porta obfs4")
except (TimeoutError, ssl.SSLError, ConnectionResetError, ErroreCanale) as exc:
    print(type(exc).__name__ + ":", exc)
PY
```

```
TimeoutError: _ssl.c:1063: The handshake operation timed out
```

**Limite dell'osservazione:** un timeout, un EOF oppure una chiusura TCP dopo un handshake non valido sono possibili a seconda dell'implementazione e del tempo trascorso. Non interpretare un singolo sondaggio come dimostrazione che un bridge sia invisibile. Il valore `_ssl.c:1063` dipende dalla versione di Python/OpenSSL.

Un normale `ClientHello` TLS è un handshake obfs4 non valido: nella cattura di riferimento non ha prodotto una risposta di protocollo utile prima del timeout. Per autenticarsi, il client obfs4 richiede i parametri del bridge (tra cui il materiale indicato come `cert`, il Node ID e la chiave di trasporto). Non è una garanzia che il TCP non verrà mai chiuso o che un censore non possa riconoscere/bloccare un IP già noto.

## Verifica automatica

```bash
make verifica-lab-bridge      # dopo la copia di sicurezza; esito anche in labs/it/laboratorio/esito-bridge
```

Il comando esegue `scripts/swap_bridge_network.py`: registra le impronte dei nodi della
rete `libro`, la ferma (controllando che non resti alcun processo `tor`: un `chutney stop`
da solo non basta), rinomina `labs/it/laboratorio/net/` in `net-libro/`, crea e avvia
`libro-bridge`, esegue `scripts/verify_bridge_lab.py` e infine rimette a posto la rete di
prima, ne confronta le impronte con quelle registrate e attende il bootstrap. La rete
`libro` non viene mai cancellata; la rete bridge viene rimossa solo se è dimostrato che
l'ha creata quella stessa esecuzione. Codici di uscita dello script: 0 controlli superati,
1 controlli falliti, 2 non eseguito (nessuna modifica), 3 ripristino da completare a mano;
`make` riporta il codice nella riga `Error N`.

I quattordici controlli: nodi presenti, bootstrap del client, descrittore del bridge,
richiesta HTTP attraverso il bridge (codice 200 **e** contenuto con un valore casuale di
quella esecuzione, servito da un server che risponde solo su `/` e non legge file), porta
obfs4 annunciata; poi, per la cattura: file nuovo, `tcpdump` realmente in ascolto, seconda
richiesta verificata durante la cattura, `tcpdump` terminato con successo, file pcap
valido, non vuoto e di quella esecuzione, analisi `tshark` riuscita, conteggi coerenti,
pacchetti con dati sulla porta obfs4, nessun pacchetto riconosciuto come TLS. Ogni errore
di processo, timeout o file mancante è un controllo fallito. L'ultimo controllo usa
un'euristica di `tshark` su una singola cattura: non è una prova di indistinguibilità né
di resistenza al sondaggio attivo.

Prima del traffico lo script controlla con `ss` che tor e obfs4proxy ascoltino solo su
`127.0.0.1` (obfs4proxy su `127.0.0.1:9909` per il bridge e su una porta locale per il
client). La cattura resta in `labs/it/laboratorio/catture/`, con il suo sha256 nell'output.

Nella prima validazione reale (28/10/2026, tor 0.4.9.13, obfs4proxy 0.0.14, TShark 4.4.19)
il risultato è stato 14/14 in tre esecuzioni consecutive. Le catture contenevano una sola
conversazione TCP fra il client PT e `127.0.0.1:9909`, 56–59 pacchetti, nessuno classificato
come TLS. Dopo il ripristino della rete `libro` l'onion service può restare irraggiungibile
per qualche minuto: lo script attende tre `chutney verify` riusciti di fila.

## Problemi noti

| Sintomo | Causa |
|---|---|
| `esito finale 3`, «arresto … non confermato», processi `tor` in stato `Z` | container creato senza `--init`: i tor fermati restano zombie. Ripristino manuale (procedura, §8), poi ricreare il container con `--init` (`make -C labs/it avvia` lo fa) |
| Il bootstrap della rete bridge non finisce | la rete precedente potrebbe occupare le porte; usare la procedura `ferma`/`pulisci` prima della nuova topologia. `pkill -x tor` uccide tutti i Tor nel container ed è ammissibile **soltanto** in un contenitore sacrificabile. |
| `011bc` non parte | i client sono nella **seconda** fase di avvio: `CHUTNEY_LAUNCH_PHASE=2 chutney start` |
| `tshark` non trova niente nel pcap | la cattura è partita dopo il traffico: lascia due secondi fra `tcpdump` e le richieste |
| I nodi hanno numeri diversi da quelli di questa pagina | la numerazione dipende dall'ordine in `labs/it/laboratorio/chutney/networks/libro-bridge`; controlla con `ls labs/it/laboratorio/net/nodes/` |
