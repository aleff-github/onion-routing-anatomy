# Procedura: esecuzione dal vivo dei laboratori dell'edizione italiana

Questa procedura serve a eseguire `make verifica-lab` e `make verifica-lab-bridge` sulla
**rete Tor privata** del libro, nell'ambiente canonico `labs/it/`, in modo ripetibile e senza
perdere chiavi e identità dei nodi. Va seguita per intero, nell'ordine.

> **Regola di sicurezza.** Tutto si svolge sulla rete Chutney del laboratorio, su `127.0.0.1`.
> Nessun passo deve contattare relay o servizi della rete Tor pubblica. L'unico accesso a
> Internet previsto è lo scaricamento esplicito di dati e sorgenti pubblici (immagine Docker,
> consenso storico da CollecTor, sorgenti di Arti), mai traffico verso relay pubblici.

## 1. Che cosa viene eseguito

| Comando | Che cosa fa | Controlli | Modifica lo stato? |
|---|---|---:|---|
| `make verifica-lab` | `scripts/verify_labs.py`: Lab 1–9, 11–20 sulla rete `libro` | 53 con dati e Arti; 41 senza | sì, temporaneamente: Lab 9 cambia e ripristina il `torrc` di `003r`; Lab 13 e 14 quelli di `009h`, `008c`, `006e`; Lab 18 le opzioni di `008c` via ControlPort |
| `make verifica-lab-bridge` | Lab 10 (`scripts/swap_bridge_network.py` + `scripts/verify_bridge_lab.py`): mette da parte la rete `libro`, crea e prova `libro-bridge`, ripristina `libro` | 14 | sì: rinomina `labs/it/laboratorio/net/` in `net-libro/` e ritorno; crea la rete `libro-bridge`, la mette in quarantena (`net-bridge-<esecuzione>/`) e la cancella solo a ripristino verificato |

Codici di uscita: `make verifica-lab` termina con 0 solo se tutti i controlli eseguiti passano;
i laboratori saltati (Lab 7, 15, 19 senza consenso; Lab 20 senza Arti) **non** contano come
superati e sono elencati nell'ultima riga («saltati (non verificati): …»). `make
verifica-lab-bridge` esegue `scripts/swap_bridge_network.py`, che termina con:

| Codice | Significato | Stato della rete `libro` |
|---:|---|---|
| 0 | 14/14 controlli sul bridge superati | ripristinata e verificata (vedi sotto) |
| 1 | controlli falliti, oppure verifica interrotta (errore, Ctrl-C, SIGTERM, `chutney init` fallito, ascolti della rete bridge non confinati al loopback) | ripristinata e verificata |
| 2 | non eseguito: un controllo preliminare non è passato | mai spostata né fermata |
| 3 | arresto dei processi non confermato, ripristino non riuscito o rete non verificabile | **intervento manuale** (§8); resta il giornale `labs/it/laboratorio/verifica-bridge.stato` |

«Ripristinata e verificata» significa: arresto di tor e obfs4proxy confermato (gli zombie non
contano) prima di spostare cartelle; sha256 di `torrc`, chiavi e identità uguali a quelli
registrati all'inizio; bootstrap; numero di processi tor uguale al numero dei nodi; nessun
obfs4proxy; tre `chutney verify` riusciti di fila a 30 s di distanza, entro 12 minuti (dopo
il riavvio l'onion service può restare irraggiungibile alcuni minuti); ascolti solo su
loopback; impronte invariate dopo il riavvio. Prima del traffico di prova lo script controlla
anche gli ascolti reali della rete bridge (`ss`): qualunque socket di tor o obfs4proxy fuori
dal loopback interrompe la prova. La cattura PCAP del Lab 10 viene conservata in
`labs/it/laboratorio/catture/` (esclusa da git: va rivista prima di pubblicarla).

`make` non restituisce il codice dello script ma il proprio (2 per qualunque errore): il
codice esatto è nella riga `make: *** [...] Error N` e in `[scambio] esito finale N`. Il
codice di `verify_bridge_lab.py` è salvato in `labs/it/laboratorio/esito-bridge` (cancellato
all'inizio di ogni esecuzione, quindi mai di una precedente).

## 2. Prerequisiti

- Linux con Docker in esecuzione nativa (il controllo dell'ambiente confronta il percorso
  montato su `/lab`; con Docker Desktop può comparire un percorso diverso).
- Python ≥ 3.11 con `cryptography` ≥ 42 (`pip install -r requirements.txt`, meglio in un
  virtualenv), `curl` sull'host.
- Immagine `torlibro-lab:latest` costruita da `labs/it/laboratorio` (`make -C labs/it immagine`;
  richiede rete per i pacchetti Debian, i sorgenti di tor 0.4.9.13 e Chutney). La build
  verifica che il tag `tor-0.4.9.13` punti al commit `3c57540…` e che Chutney sia al commit
  `6cc1588…`. Dietro un proxy HTTPS che re-termina TLS (ambienti cloud):
  `make -C labs/it immagine PROXY_CA=/percorso/ca-del-proxy.crt` (rete dell'host per la
  build, apt in HTTPS, CA passata come segreto e assente dall'immagine finale).
- Per una validazione completa (53 controlli):
  - consenso storico: `make -C labs/it data` (controlla solo l'intestazione, non le firme);
  - certificati delle autorità del periodo in `labs/it/dati/collector/certs` (Lab 15,
    passo 6; facoltativo: senza, quel controllo non viene eseguito);
  - Arti 2.6.0 compilato in `labs/it/vendor/arti` (cap. 30, passo 1).
- Porte libere su `127.0.0.1`: 5100–5111 (ORPort), 7100–7111 (DirPort), 8000–8011
  (ControlPort), 9000–9011 (SocksPort), 8080 e 8081 (server di prova), 8095 (Lab 16),
  9150 (Arti), 9909 (obfs4 nella rete `libro-bridge`); 5300/UDP per il resolver degli exit,
  solo durante il Lab 18. Tutti i servizi della rete, DirPort compresi, ascoltano solo su
  `127.0.0.1` (`python3 scripts/loopback_network.py controlla`).

- Host senza IPv6 (alcuni container cloud): `make -C labs/it avvia` se ne accorge e passa
  `CHUTNEY_DISABLE_IPV6=1` al container; se si lavora come root, il verificatore avvia Arti
  con `-o application.allow_running_as_root=true`. Gli exit risolvono i nomi solo con il
  resolver della rete (`labs/it/laboratorio/dns_locale.py`, via `CHUTNEY_DNS_CONF`), mai con quello
  dell'host (sezione I della relazione, LV-13).

## 3. Controlli preliminari (solo letture)

Dalla radice del repository:

```bash
git status --short                      # nessuna modifica locale inattesa
git rev-parse HEAD                      # da annotare con i risultati
docker ps -a --format '{{.Names}}\t{{.Status}}\t{{.Mounts}}'
#   - nessun altro laboratorio attivo (torbook-network, torbook-es-network, …):
#     usano le stesse porte;
#   - torlibro-rete, se esiste, deve montare labs/it/laboratorio (vedi sotto)
ss -ltnp | grep -E ':(5[01][0-9]{2}|71[01][0-9]|80[01][0-9]|90[01][0-9]|8080|8081|8095|9150|9909)\b'
test ! -e labs/it/laboratorio/net-libro && echo "nessuna net-libro residua"
test ! -e labs/it/laboratorio/verifica-bridge.stato && echo "nessuno scambio interrotto"
ls -d labs/it/laboratorio/net-bridge-* 2>/dev/null   # quarantene rimaste (vedi §8)
ls labs/it/laboratorio/net/nodes/ 2>/dev/null   # rete libro: 000a … 009h, se già creata
```

## 4. Copia di sicurezza (obbligatoria prima di ogni esecuzione)

`labs/it/laboratorio/net/` contiene chiavi e identità dei nodi. Copiala **fuori dal repository**
(non deve mai finire in git):

```bash
mkdir -p ~/torlab-copie
cp -a labs/it/laboratorio/net ~/torlab-copie/net-$(date +%Y%m%d-%H%M%S)
```

## 5. Avvio della rete e controlli di salute

```bash
make -C labs/it avvia                    # solo se la rete non è già avviata
make -C labs/it/laboratorio verifica             # atteso: successes:4 failures:0
python3 scripts/loopback_network.py controlla   # atteso: "[OK ] tutto su 127.0.0.1"
python3 scripts/verify_labs.py --controlla-ambiente
#   atteso: "[OK ] Ambiente: torlibro-rete monta …/labs/it/laboratorio su /lab; nodi in …"
python3 scripts/verify_labs.py --solo-offline   # Lab 2, 7, 15, 19, senza rete
```

Se il controllo dell'ambiente fallisce, **fermarsi**: gli script eseguiti nel container e i
file letti dall'host apparterrebbero a reti diverse.

## 6. Esecuzione

Salva sempre l'output completo, fuori dal repository:

```bash
mkdir -p ~/torlab-esiti
make verifica-lab 2>&1 | tee ~/torlab-esiti/verifica-lab-$(date +%Y%m%d-%H%M%S).log
echo "codice di uscita: ${PIPESTATUS[0]}"
```

Poi, solo se il passo precedente si è concluso e dopo una **nuova** copia di sicurezza (§4):

```bash
make verifica-lab-bridge 2>&1 | tee ~/torlab-esiti/verifica-lab-bridge-$(date +%Y%m%d-%H%M%S).log
echo "codice di uscita: ${PIPESTATUS[0]}"
make -C labs/it/laboratorio verifica             # la rete libro ripristinata funziona?
```

Lo script confronta da sé le impronte della rete ripristinata con quelle registrate
all'inizio e termina con 3 se differiscono. Il confronto con la copia di sicurezza è un
controllo indipendente in più:

```bash
COPIA=~/torlab-copie/net-AAAAMMGG-HHMMSS   # la copia fatta prima del bridge
for n in labs/it/laboratorio/net/nodes/*/fingerprint; do
  cmp -s "$n" "$COPIA/nodes/$(basename "$(dirname "$n")")/fingerprint" || echo "DIVERSA: $n"
done
```

## 7. Come leggere e registrare i risultati

- Ogni riga `[OK ]` o `[NO!]` è un controllo; `[--]` è un laboratorio saltato.
- Una validazione è **completa** solo con `53/53` e nessun laboratorio saltato; con dati o
  Arti mancanti l'esito è parziale e va registrato come tale.
- Confronto con il libro: i controlli verificano valori stampati nei capitoli (finestre 124 e
  500 del cap. 11, 9 circuiti su 30 del cap. 15, 9358 relay e quote di banda del cap. 24, 8/9
  celle `RELAY_EARLY` del cap. 27, 18,2% e mediana 14 del cap. 29, ecc.). Per i listati che
  dipendono dal consenso pubblico esegui anche `python3 scripts/verify_listings.py`.
- Annota nel diario: data, `git rev-parse HEAD`, versione di tor nel container
  (`docker exec torlibro-rete tor --version`), totali, laboratori saltati, eventuali `[NO!]`
  con la riga completa, esito del confronto delle impronte.

Un `[NO!]` che si ripete sulla stessa riga indica un errore del codice o del libro; un
fallimento isolato che scompare al tentativo successivo è tipico di una rete piccola
(`labs/it/wiki/Verifica-automatica.md`), ma va comunque registrato.

## 8. Ripristino

**Un laboratorio si interrompe durante `make verifica-lab`.** I `torrc` modificati vengono
ripristinati nei blocchi `finally`; se il processo è stato ucciso, confronta i `torrc` di
`003r`, `006e`, `008c` e `009h` con la copia di sicurezza e, se diversi, ricopiali e manda
`HUP` al nodo (`docker exec torlibro-rete sh -c 'kill -HUP $(cat /lab/net/nodes/NNNx/pid)'`).

**`make verifica-lab-bridge` e le interruzioni.** Errori, Ctrl-C e SIGTERM durante la
verifica vengono gestiti dallo script: annulla la verifica, ripristina la rete `libro` e
termina con 1 (durante il ripristino Ctrl-C e SIGTERM sono ignorati). Restano senza
ripristino automatico solo la terminazione forzata (SIGKILL, spegnimento della macchina) e
i casi in cui lo script stesso esce con 3. In entrambi resta il giornale
`labs/it/laboratorio/verifica-bridge.stato` e, finché esiste, né `make verifica-lab-bridge` né
`make -C labs/it avvia` / `make -C labs/it/laboratorio pulisci` ripartono.

Procedura manuale (non cancellare niente prima di aver fatto tutti i controlli):

```bash
cat labs/it/laboratorio/verifica-bridge.stato          # fase raggiunta e impronte della rete libro
ls -d labs/it/laboratorio/net labs/it/laboratorio/net-libro labs/it/laboratorio/net-bridge-* 2>/dev/null
ls labs/it/laboratorio/net-libro/nodes/ 2>/dev/null    # 000a … 009h: è la rete libro
ls labs/it/laboratorio/net/nodes/ labs/it/laboratorio/net/nodes.*/ 2>/dev/null   # *ba, *br, *bc: rete bridge
docker exec torlibro-rete chutney stop
docker exec torlibro-rete sh -c 'pkill -x tor || true'
docker exec torlibro-rete pgrep -x tor || echo "nessun tor attivo"
```

1. Se esiste `net-libro/` e `net/` contiene **solo** nodi della rete bridge, sposta la
   rete bridge **fuori dal repository** invece di cancellarla, poi rimetti a posto
   la rete libro:
   `mv labs/it/laboratorio/net ~/torlab-copie/net-bridge-$(date +%Y%m%d-%H%M%S)` e
   `mv labs/it/laboratorio/net-libro labs/it/laboratorio/net`.
2. Se `net-libro/` non esiste e `net/nodes/` mostra 000a … 009h, la rete libro è già al
   suo posto (lo script si è fermato al riavvio o al confronto).
3. Confronta le impronte con quelle del giornale e con la copia di sicurezza (§6); se
   differiscono, ripristina la copia di sicurezza.
4. `make riavvia` e `make -C labs/it/laboratorio verifica` (atteso `failures:0`).
5. Solo a rete verificata: `rm labs/it/laboratorio/verifica-bridge.stato`. Le cartelle
   `net-bridge-*` rimaste sono reti bridge di prova: cancellale solo dopo aver controllato
   che contengano nodi `*ba`, `*br`, `*bc` (git le ignora, ma contengono chiavi).

Se `net/` contiene qualcosa che non è né la rete libro né la rete bridge, fermarsi e
non toccarla: è il caso in cui lo script rifiuta di procedere.

**La rete `libro` non riparte.** Prima `make riavvia` (rimuove i `pid` rimasti e rilancia le
due fasi). Se il container non esiste più, ricrearlo con `make -C labs/it avvia` esegue
`chutney init`: per conservare le identità, ripristina comunque la copia di sicurezza se le
impronte cambiano.

**Dopo un riavvio della macchina** il container `torlibro-rete` è fermo (`Exited`) ma
`labs/it/laboratorio/net/` è intatta. Senza `chutney init`, dopo la copia di sicurezza (§4):

```bash
docker rm torlibro-rete                  # solo il container fermo: i dati sono in net/
docker run -d --init --name torlibro-rete --network host -v "$PWD/labs/it/laboratorio":/lab \
  -e CHUTNEY_DISABLE_IPV6=1 -e CHUTNEY_DNS_CONF=/lab/dns_locale.conf \
  -u "$(id -u):$(id -g)" torlibro-lab:latest sleep infinity   # come in make avvia
make riavvia
make -C labs/it/laboratorio verifica             # l'onion service può richiedere ~8 minuti
```

(`CHUTNEY_DISABLE_IPV6=1` solo su host senza IPv6.) Dopo una pausa lunga, per qualche minuto
`chutney verify` può fallire sull'onion service: il servizio ha pubblicato descrittori
calcolati sul consenso in cache e gli HSDir rifiutano i successivi («revision counter … is
greater or equal»), finché non cambia il periodo (circa 8 minuti nella rete di prova).

**Rete creata prima del 28/10/2026.** I suoi `torrc` hanno `DirPort 710x` senza indirizzo
(ascolto su `0.0.0.0`) e gli exit usano `/etc/resolv.conf`. A rete ferma, senza toccare
chiavi né identità: `python3 scripts/loopback_network.py migra` (mostra), poi `migra
--applica`, poi la ripresa descritta sopra. In alternativa si ricrea la rete con
l'immagine nuova.

**Ultima risorsa.** `make -C labs/it/laboratorio pulisci` cancella `labs/it/laboratorio/net/` con tutte le
chiavi: usarlo solo su una rete davvero sacrificabile, dopo la copia di sicurezza.

## 9. Che cosa è stato verificato di questa procedura

Verificato senza rete (26/10/2026): risoluzione di tutti i comandi `make` (`make -n`);
controllo dell'ambiente con container usa e getta (montaggio errato → stop; corretto → OK);
ripiego di `fuga_dns.py` sulla porta 8080 già occupata; formato dell'output degli script
canonici rispetto alle attese del verificatore.

Verificato senza rete (26/10/2026, sera): `make test` (`scripts/tests/`, 100
test, nessun Docker, Tor, Chutney o collegamento esterno: i test lo impediscono e lo
controllano) copre server HTTP del Lab 10, richiesta che genera il traffico, avvio, timeout
e terminazione di `tcpdump`, cattura mancante, vuota, non valida o vecchia, errori e output
incoerenti di `tshark`, e lo scambio delle reti con un container simulato (successo,
controlli falliti, verificatore in errore o interrotto, `chutney init` fallito, `net-libro`
residua, giornale presente, rete che non si ferma, ripristino fallito, impronte cambiate,
cartella estranea, SIGTERM, Ctrl-C durante il ripristino, codici di uscita fino a `make`).

**Non** sono stati eseguiti i laboratori sulla rete, né lo scambio reale con Docker e
Chutney: comportamento di `tcpdump`/`tshark` reali nell'immagine, tempi di `chutney
bootstrap` e `wait_for_bootstrap`, permessi dei file creati dal container. La prima
esecuzione reale va registrata nel diario.
