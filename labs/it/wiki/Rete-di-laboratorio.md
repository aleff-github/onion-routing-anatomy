# La rete di laboratorio

Una rete Tor completa, con le sue autorità, i suoi relay e il suo onion service, che
gira sui servizi di loopback `127.0.0.1` dentro un container Docker. **Attenzione:** il Makefile usa `--network host`, quindi il container **condivide la rete dell'host** e non costituisce una barriera di isolamento della rete. È l'oggetto su cui si svolge quasi ogni laboratorio del libro, descritto per esteso nel **capitolo 19**.

## Perché una rete propria

Perché sulla rete Tor pubblica non si può sperimentare. Ogni pacchetto che vi si manda
attraversa i relay di volontari e si mescola al traffico di persone che da quella rete
dipendono per la propria sicurezza. Un esperimento che su una rete privata è una riga di
codice, sulla rete pubblica è un attacco a degli sconosciuti.

Su una rete propria, invece, si possono fare cose altrimenti impensabili: rompere un MAC
per vedere come reagisce un relay, superare il limite delle celle `RELAY_EARLY`,
provocare le difese anti-DoS, decifrare il proprio TLS e leggere le celle una per una.

## Topologia

Dieci nodi, tutti su `127.0.0.1`:

| Nodo | Ruolo | ORPort | ControlPort | Altro |
|---|---|---:|---:|---|
| `000a`, `001a`, `002a` | directory authority, e anche relay | 5100–5102 | 8000–8002 | DirPort 7100–7102 |
| `003r`, `004r`, `005r` | relay intermedi | 5103–5105 | 8003–8005 | |
| `006e`, `007e` | exit | 5106, 5107 | 8006, 8007 | escono verso `127.0.0.0/8` |
| `008c` | client | — | 8008 | SocksPort 9008 |
| `009h` | onion service v3 | — | 8009 | porta virtuale 5858 → `127.0.0.1:4747` |

**La regola delle porte**: il nodo numero *n* usa ORPort `5100+n`, ControlPort `8000+n`
e, se è un client, SocksPort `9000+n`. Vale per tutta la rete e per tutti i laboratori:
`5103` è sempre `003r`, `9008` è sempre il client.

Chutney chiama i nodi `test000a`, `test003r` e così via; nel libro e qui si usa la forma
breve.

Tre differenze importanti rispetto alla rete pubblica, da tenere a mente quando si
interpretano i risultati:

- le autorità votano **ogni 20 secondi** invece che ogni ora, così un consenso nuovo
  arriva in meno di un minuto invece che in un'ora;
- ci sono tre relay intermedi in tutto, quindi i vincoli di diversità del percorso
  (relay distinti, /16 distinte, famiglie) non si possono osservare come sulla rete
  vera: per quelli c'è il [Laboratorio 7](Laboratorio-07-Percorsi.md), che lavora su un
  consenso pubblico;
- i nodi condividono lo stesso indirizzo IP, il che rende alcune protezioni inefficaci
  per costruzione.

La seconda topologia, `libro-bridge`, è **alternativa** a `libro`, non una sua estensione avviabile in parallelo: comprende **12 nodi** (3 autorità ordinarie, 1 autorità bridge, 3 relay intermedi, 2 exit, 1 bridge obfs4 e 2 client, uno dei quali usa il bridge) e **non include l'onion service `009h`**. È destinata al [Laboratorio 10](Laboratorio-10-Bridge.md); per gli esperimenti con l'onion service occorre tornare alla topologia standard.

## Comandi

Esegui i comandi della rete **solo sull'ambiente di laboratorio**: Docker con `--network host` condivide le porte con il computer, anche se i servizi sono configurati su loopback. Non avviare contemporaneamente più edizioni linguistiche: i nodi usano le stesse porte. Il comando `pulisci` elimina la directory `net/`, quindi **chiavi, identità e stato**; salva separatamente soltanto i dati non sensibili che vuoi conservare.

Dalla cartella `labs/it/laboratorio/`:

```bash
make immagine    # una volta sola: compila tor dai sorgenti nell'immagine
make avvia       # crea il container, genera i nodi, attende il bootstrap
make verifica    # chutney verify: traffico di prova end-to-end
make stato       # quanti nodi sono vivi
make shell       # una shell dentro il container
make ferma       # ferma i nodi e rimuove il container; labs/it/laboratorio/net/ resta
make pulisci     # come sopra, ma cancella anche labs/it/laboratorio/net/

make avvia RETE=libro-bridge    # la topologia con il bridge
```

Dalla radice del repository:

```bash
make riavvia              # riavvia i nodi Tor solo se il container è ancora presente
make verifica-lab         # avvia i controlli disponibili dei laboratori italiani
make verifica-lab-bridge  # prova il Laboratorio 10 nella topologia bridge
```

`make riavvia` opera **dentro un container già esistente** tramite `docker exec torlibro-rete`: è utile dopo l'arresto dei **soli processi Tor**, non dopo `make -C labs/it/laboratorio ferma`, che rimuove anche il container. Dopo `ferma`, riparti da `make -C labs/it/laboratorio avvia` (o ricrea prima l'ambiente se hai eseguito `pulisci`). Il riavvio interno ripulisce i PID rimasti e usa **due fasi** — prima i relay, poi client e onion service (`CHUTNEY_LAUNCH_PHASE=2`). Il numero di verifiche effettivamente eseguite da `verifica-lab` dipende da prerequisiti e disponibilità dei dati: un controllo saltato non è un PASS.

## Dove sono le cose

```
labs/it/laboratorio/net/nodes/            i dieci nodi (symlink a nodes.<timestamp>)
labs/it/laboratorio/net/nodes/003r/
    torrc                 la configurazione, generata da Chutney
    fingerprint           l'identità RSA
    fingerprint-ed25519   l'identità Ed25519, quella che i laboratori verificano
    notice.log            il registro: la prima cosa da guardare quando qualcosa non va
    pid
labs/it/laboratorio/net/nodes/008c/cached-microdescs.new    le chiavi ntor dei relay, viste dal client
labs/it/laboratorio/net/nodes/009h/hidden_service/hostname  l'indirizzo .onion del servizio
```

`labs/it/laboratorio/net/` **non è versionata**: contiene chiavi private (di una rete giocattolo, ma sempre chiavi). La directory viene **cancellata** e ricreata con `make -C labs/it/laboratorio pulisci && make -C labs/it/laboratorio avvia` eseguiti dalla radice del repository.
Ogni rigenerazione cambia le identità dei nodi: le impronte che compaiono negli output
del libro e di questa wiki saranno diverse dalle tue, e va bene così.

Il modulo `torlab.laboratorio` legge quei file per te:

```python
from torlab.laboratorio import relay
r = relay("003r")
print(r.porta, r.id_ed.hex()[:16], r.ntor.hex()[:16])
```

## Regole di condotta

Gli script dei laboratori generano di proposito traffico anomalo: celle malformate,
superamento di limiti, sondaggi ripetuti, cattura di pacchetti. Vanno eseguiti **solo**
su questa rete privata. Farlo contro relay o servizi reali danneggia chi li usa e, in
molti ordinamenti, è un reato: il capitolo 25 entra nel merito.

I laboratori 7, 15 e 19 analizzano **documenti storici pubblici** scaricati da CollecTor, anziché inviare traffico sperimentale ai relay della rete Tor pubblica. Il download iniziale usa **HTTPS** e richiede una connessione Internet; non è una prova di rete isolata in senso assoluto.
