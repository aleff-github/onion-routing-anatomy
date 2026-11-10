# Risoluzione dei problemi

Le voci seguenti documentano problemi riscontrati durante la preparazione dell'edizione italiana di riferimento, con le cause ipotizzate o identificate allora. **Non garantiscono che ogni messaggio o causa sia invariato nelle versioni successive**. La rete Docker usa `--network host`: pur impiegando indirizzi di loopback, non è una rete isolata dallo stack dell'host.

## La rete non parte

**`docker: Error response from daemon: Conflict. The container name "torlibro-rete" is already in use`**
Esiste già un container con quel nome, anche se non è in esecuzione. Controlla prima che appartenga al **tuo ambiente di prova** con `docker ps -a`; solo dopo puoi eseguire `make -C labs/it/laboratorio ferma` e riprovare. Gli altri ambienti linguistici possono inoltre occupare le stesse porte sull'host.

**Il bootstrap non finisce, i nodi restano al 5 %**
Le cause possibili comprendono porte occupate, autorità non raggiungibili e processi Tor rimasti dalla rete precedente. **Non avviare `pkill -x tor` alla cieca:** terminerebbe tutti i Tor con quel nome nel container. Verifica stato e processi prima di agire:

```bash
make -C labs/it/laboratorio stato
docker ps -a
ss -ltnp | grep -E ':(510[0-9]|710[0-9]|800[0-9]|900[0-9])' || true
```

Se il container `torlibro-rete` contiene solo il laboratorio da eliminare, fermalo con `make -C labs/it/laboratorio ferma` e ricrealo tramite `make -C labs/it/laboratorio avvia`. Una terminazione per nome non distingue i singoli nodi. Evita anche `pkill -f "tor -f"`: il criterio può includere la shell chiamante.

**I nodi risultano avviati ma non rispondono**
Dopo un arresto brusco possono restare file `pid`. **Solo se il container `torlibro-rete` esiste ancora**, dalla radice:

```bash
make riavvia
```

Il target rimuove i file PID e rilancia le **due** fasi di avvio. **Se è stato eseguito `make -C labs/it/laboratorio ferma`, il container non esiste più** e `make riavvia` non può funzionare: usa `make -C labs/it/laboratorio avvia` (o `pulisci` solo se vuoi perdere lo stato). Un solo `chutney start` può omettere client e servizio onion della fase `CHUTNEY_LAUNCH_PHASE=2`.

**`chutney verify` fallisce con `Address already in use`**
La collisione può riguardare un server di prova lasciato su 8080/4747, un'altra rete linguistica o le porte ORPort/ControlPort/SOCKS dei nodi. Prima di fermare qualunque processo identifica proprietario e porta:

```bash
ss -ltnp | grep -E ':(8080|4747|9008)'
```

## `make verifica-lab` si ferma subito

**`impossibile occupare la porta 8080`**
La suite avvia il proprio server di prova sulla 8080, e ne serve uno solo. Chiudi il
server che hai lasciato aperto per i Laboratori 5, 11 o 16.

**Tutti i laboratori di rete falliscono**
La rete potrebbe non essere avviata: verifica con `make -C labs/it/laboratorio stato` e controlla `labs/it/laboratorio/net/nodes/000a/notice.log` **se esiste**, insieme al log del client `008c`. Il verificatore usa la rete di `labs/it/laboratorio`.

**Un laboratorio fallisce una volta e poi passa**
La rete ha tre relay intermedi: ogni tanto un circuito non si costruisce al primo
tentativo (`CREATE2 rifiutata (comando 4)` significa che è arrivato un `DESTROY`).
Un nuovo tentativo, dopo aver conservato i log, può essere utile. **Non equivale a una prova di correttezza**: anche guasti intermittenti meritano indagine, soprattutto se la cella `DESTROY` compare ripetutamente.

**Falliscono solo i controlli dei Laboratori 7, 15 e 19**
Il verificatore italiano confronta valori storici ottenuti dal consenso del **23 settembre 2026**, in `labs/it/dati/collector/`. Se il file manca, questi controlli sono segnalati come **SKIP**, non PASS; se cambia lo snapshot, cambiano i numeri.

## Singoli laboratori

**L'onion service smette di rispondere, nei log `400 Invalid HS descriptor`**
Nell'esperimento storico era stata osservata una directory `authorized_clients` **vuota**, ma quel messaggio `400` non è una diagnosi universale. **Attenzione:** una directory vuota non abilita la protezione: Tor richiede almeno un file `.auth` valido, nel formato `descriptor:x25519:<chiave-pubblica-base32>`. Senza autorizzazione attiva, il servizio può essere accessibile a chi conosce l'indirizzo. Se il [Laboratorio 13](Laboratorio-13-Scoperta-ristretta.md) si interrompe, prima controlla i file e il `torrc` senza cancellare nulla:

```bash
ls -la labs/it/laboratorio/net/nodes/009h/hs_ristretto/authorized_clients/
grep -nE 'HiddenServiceDir|HiddenServicePort' labs/it/laboratorio/net/nodes/009h/torrc
```

Lo script del laboratorio aggiornato segnala HUP al **PID verificato** del nodo e tenta di ripristinare i file `torrc`. **Non usare** il vecchio `pkill -HUP -f 009h/torrc`, né eliminare le chiavi alla cieca. Se non puoi ripristinare con certezza il singolo servizio, valuta la rigenerazione dell'**intera rete usa e getta** dopo aver verificato che nessun dato debba essere conservato. Mai usare questa procedura per un servizio onion reale.

**Il client del laboratorio muore dopo una modifica al torrc**
Un percorso dell'**host** in un'opzione che tor legge **dentro** il container
(`ClientOnionAuthDir`, `HiddenServiceDir`). tor esce con un errore di configurazione. I
percorsi interni si ricavano dal `DataDirectory` del nodo.

**Un exit risponde `END TORPROTOCOL` a tutto**
Stai usando un circuito di **un solo salto**. Un exit rifiuta di uscire da un circuito di
un salto: sarebbe un proxy aperto. Costruiscine uno di tre.

**`LookupError: nessun microdescrittore per 003r`**
Il client non ha ancora scaricato i microdescrittori. Aspetta un minuto dopo l'avvio.

**`il relay ha un'identità diversa da quella attesa`, ma la porta è giusta**
Hai rigenerato la rete: le chiavi sono nuove. Ogni `make -C labs/it/laboratorio pulisci` cambia tutte le
identità. Rileggi `fingerprint-ed25519`.

**Il pcap è vuoto, o `tshark` non decifra niente**
Tra le cause **possibili**, senza ordine di frequenza verificato, ci sono cattura iniziata troppo tardi, permessi insufficienti per `tcpdump` e `SSLKEYLOGFILE` impostato **dopo** il socket TLS. Controlla l'effettiva disponibilità delle chiavi di sessione; non è garantito che qualunque processo Tor le esporti in quel formato.

## Riportare le cose a posto

La rete di laboratorio è usa e getta. Se qualcosa è in uno stato incomprensibile, la
soluzione più rapida è quasi sempre ricominciare:

```bash
make -C labs/it/laboratorio pulisci
make -C labs/it/laboratorio avvia
make -C labs/it/laboratorio verifica        # verifica la rete Chutney attiva; esito da osservare
make verifica-lab           # verificatore italiano (labs/it); alcune prove possono essere SKIP
```

`pulisci` elimina **tutto** `labs/it/laboratorio/net/`, comprese identità onion, chiavi e risultati locali: eseguilo **solo dopo aver controllato** che siano davvero sacrificabili. Non sono garantiti né i tempi di ricostruzione né un numero fisso di test superati. Alcune prove necessitano dei dati CollecTor o di Arti compilato.

## Se il problema non è qui

Il registro di ogni nodo è in `labs/it/laboratorio/net/nodes/<nodo>/notice.log`, e quello del client è
spesso il più informativo. Per i dettagli, `info.log` se il nodo è configurato per
scriverlo.

Quando un esperimento dà un risultato che non torna, il metodo che mi ha salvato più
volte è: cercare un punto intermedio in cui confrontare il proprio risultato con quello
di un'implementazione di riferimento. Il client `tor` della rete ha una porta di
controllo, risponde a `GETINFO` e sa fare quasi tutto quello che sappiamo fare noi — con
il vantaggio di essere quasi certamente corretto.
