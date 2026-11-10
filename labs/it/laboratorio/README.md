# Rete Tor privata per i laboratori

Gli esperimenti attivi dell'edizione italiana sono destinati esclusivamente alla rete privata Chutney,
mai ai relay Tor pubblici o a servizi di terzi. Docker usa `--network host`, quindi condivide
lo stack di rete dell'host: non costituisce isolamento di rete. Usare un host di test controllato.
La documentazione completa è nel capitolo 19; questa è la scheda di riferimento rapido.

## Contenuto

| File | Che cos'è |
|---|---|
| `Dockerfile` | immagine con tor 0.4.9.13 compilato dai sorgenti (`--enable-gpl`, quindi con la prova di lavoro), Chutney, obfs4proxy, snowflake-client, stem, tshark, curl |
| `Makefile` | `immagine`, `avvia`, `verifica`, `stato`, `shell`, `ferma`, `pulisci` |
| `chutney/networks/libro` | la rete usata da quasi tutti i laboratori |
| `chutney/networks/libro-bridge` | variante con autorità dei bridge, bridge obfs4 e client che lo usa (Laboratorio 10) |
| `net/` | stato generato: chiavi, configurazioni, log e dati dei nodi. Non è versionato |
| `catture/` | PCAP del Laboratorio 10 conservati da `make verifica-lab-bridge`. Non versionati: vanno rivisti prima di pubblicarli |
| `*.py` | gli script dei laboratori 11, 13, 14, 16, 17, 18 e 20 |
| `dns_locale.py`, `dns_locale.conf` | resolver minimo degli exit (solo `127.0.0.1:5300`, nessun inoltro), attivo durante il Laboratorio 18 |
| `chutney-dirport-loopback.patch` | una riga per Chutney, applicata dal `Dockerfile`: i DirPort ascoltano su `127.0.0.1` come gli ORPort |

## Comandi

```bash
make immagine              # una volta sola: compila tor nell'immagine (alcuni minuti)
# dietro un proxy HTTPS che re-termina TLS: make immagine PROXY_CA=/percorso/ca-del-proxy.crt
make avvia                 # crea e avvia la rete; attende il bootstrap
make verifica              # chutney verify: traffico di prova end-to-end
make stato                 # quanti nodi sono attivi
make shell                 # una shell dentro il container
make ferma                 # ferma i nodi, conserva net/
make pulisci               # ferma e cancella net/

make avvia RETE=libro-bridge   # la topologia con il bridge
```

Dalla radice del repository, `make riavvia` opera sul solo container italiano e può rimettere in piedi la rete dopo uno stop
(rimuove i file `pid` rimasti indietro e avvia le due fasi: prima i relay, poi i client).

## La topologia `libro`

Dieci nodi, tutti su `127.0.0.1`:

| Nodo | Ruolo | ORPort | ControlPort | Altro |
|---|---|---:|---:|---|
| `000a`–`002a` | directory authority (e relay) | 5100–5102 | 8000–8002 | DirPort 7100–7102 |
| `003r`–`005r` | relay intermedi | 5103–5105 | 8003–8005 | |
| `006e`, `007e` | exit | 5106, 5107 | 8006, 8007 | escono verso `127.0.0.0/8` |
| `008c` | client | — | 8008 | SocksPort 9008 |
| `009h` | onion service | — | 8009 | porta virtuale 5858 → `127.0.0.1:4747` |

Regola delle porte per i ruoli applicabili: i relay usano ORPort `5100+n`, i nodi ControlPort
`8000+n` e i client SocksPort `9000+n`; un client o onion service non diventa per questo un relay.
La configurazione di riferimento descrive votazioni delle autorità ogni circa 20 secondi;
i tempi effettivi di bootstrap e consenso richiedono una verifica runtime.

## Se qualcosa non funziona

- **`chutney verify` fallisce con «address already in use»**: un programma occupa una porta
  del laboratorio (spesso un server di prova sulla 4747 o sulla 8080 lasciato acceso).
  Chiudilo e riprova.
- **I nodi risultano attivi ma non rispondono**: i file `pid` possono restare indietro dopo
  un arresto brusco. Usa `make riavvia` dalla radice.
- **Un laboratorio fallisce una volta sola**: la rete è piccola e a volte un circuito non si
  costruisce al primo tentativo. Rieseguire è legittimo; se fallisce sempre, è un difetto.
- **Il client non riparte dopo `chutney start`**: i client sono nella seconda fase di avvio,
  `CHUTNEY_LAUNCH_PHASE=2 chutney start`.

## Avvertenza

Gli script di questa cartella generano traffico anomalo di proposito (limiti anti-DoS,
celle malformate, sondaggi). Vanno eseguiti solo su questa rete privata: farlo contro
relay o servizi reali è dannoso per chi li usa e, in molti ordinamenti, illecito
(capitolo 25).
