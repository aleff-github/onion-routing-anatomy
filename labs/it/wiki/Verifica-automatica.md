# Verifica automatica

La repository contiene codice e procedure per **rieseguire molti risultati sperimentali** del libro. La loro presenza non significa che ogni affermazione sia già stata verificata su tutte le versioni, né che ogni laboratorio sia coperto da un controllo automatico. Questa pagina separa test unitari, verifiche dinamiche e limiti rimasti aperti.

## I tre comandi

```bash
PYTHONPATH=labs/it/codice python3 -m pytest -q labs/it/codice/torlab/test   # test offline italiani
make verifica-lab                                  # rete avviata con make -C labs/it avvia
# make verifica-lab-bridge                          # prima leggere le precauzioni sotto
```

### I test del codice

Usano moduli e fixture locali e non richiedono Chutney. **Durata, numero di test ed esito** dipendono dall'ambiente e vanno misurati, non presupposti. Le categorie principali sono:

- i **formati binari**, con i vettori di test ufficiali delle specifiche dove esistono
  (proposta 332 per ntor-v3, proposta 216 per l'HKDF di ntor). Un handshake
  crittografico non si verifica «facendolo funzionare»: due implementazioni sbagliate
  allo stesso modo si capirebbero benissimo;
- i **casi di errore**: firme alterate, certificati scaduti, identità sbagliata,
  lunghezze fuori intervallo. Un test che prova solo il caso valido non dimostra nulla,
  perché lo supererebbe anche un verificatore che accetta tutto;
- la **riproducibilità** dei risultati numerici stampati nel libro.

### `make verifica-lab`

Il target invoca **esclusivamente** `scripts/verify_labs.py` nell'ambiente italiano `labs/it/` (codice in `labs/it/codice`, rete in `labs/it/laboratorio/net`), che deve essere già avviato con `make -C labs/it avvia`. Prima di qualunque prova controlla, in sola lettura, che il container `torlibro-rete` monti proprio `labs/it/laboratorio` su `/lab`; altrimenti si ferma, invece di mescolare due reti. `python3 scripts/verify_labs.py --solo-offline` esegue soltanto i passi senza rete (`lab2`, `lab7`, `lab15`, `lab19`). Il `main()` richiama un insieme definito di funzioni (18 passi, alcuni dedicati a più laboratori): **non garantisce la copertura automatica di tutte e venti le attività**, né un numero fisso di controlli. Il programma apre anche un server HTTP locale sulla porta 8080. L'ambiente Docker usa `--network host`.

È un **controllo di regressione parziale** per individuare esperimenti da riesaminare quando cambiano Tor o il codice. Non sostituisce la lettura critica dei risultati. Prima di aggiornare `\aggiornatoal` di un capitolo bisogna verificare che i controlli pertinenti siano stati realmente eseguiti, senza SKIP.

Il ciclo principale cattura le eccezioni dei passi e continua; **errori precedenti al ciclo** (per esempio porta 8080 occupata), interruzioni forzate e problemi nei ripristini restano possibili. Il totale riguarda soltanto le condizioni effettivamente valutate.

```
[OK ] Lab 1: canale verso 003r — v5, TLS TLSv1.3 TLS_AES_256_GCM_SHA384
...
<PASS>/<controlli eseguiti> controlli superati  # formato illustrativo, non risultato attuale
```

I passi `lab2`, `lab7`, `lab15` e `lab19` non dipendono dai relay privati; `lab7`, `lab15` e `lab19` leggono il consenso storico in `labs/it/dati/collector/` (`make -C labs/it data`), mentre `lab2` usa dati sintetici. Se lo snapshot manca, stampano **SKIP e ritornano senza aggiungere condizioni** a `esiti`; un totale positivo non significa che questi passi siano PASS. L'avvio del verificatore tenta comunque di aprire il server 8080 prima del ciclo.

### `make verifica-lab-bridge`

Il Laboratorio 10 richiede `libro-bridge`. **Il target non è atomico né sicuro da lanciare senza preparazione** (comincia controllando che il container usi `labs/it/laboratorio`, come `make verifica-lab`): termina i processi `tor` per nome nel container, sposta `labs/it/laboratorio/net/` in `labs/it/laboratorio/net-libro`, crea una nuova topologia, esegue `scripts/verify_bridge_lab.py` e tenta di ripristinare quella precedente. Alcuni comandi del Makefile sono preceduti da `-` e **ignorano errori**, compreso quello del verificatore bridge; un'interruzione può lasciare lo stato incoerente. L'esito dello script è scritto in `labs/it/laboratorio/esito-bridge` e va controllato separatamente, assieme ai log, allo stato dei nodi e alle identità. Prima di procedere verifica che sia solo la rete usa e getta, esegui copie dei dati da conservare e non avviare altri laboratori. **Va lanciato solo seguendo la procedura di `docs/it/procedura-laboratori-dal-vivo.md`**, che prevede la copia di sicurezza di `labs/it/laboratorio/net/` e i controlli di ripristino.

## Che cosa significa un fallimento

| Sintomo | Di solito significa |
|---|---|
| Un laboratorio fallisce **una volta sola**, poi passa | conserva i log e indaga: un tentativo successivo riuscito non dimostra che il primo fallimento sia trascurabile |
| Un laboratorio fallisce **sempre**, sulla stessa riga | verifica codice, dati, rete, dipendenze, protocolli e testo |
| **Tutti** i laboratori di rete falliscono | la rete non è avviata, o i nodi sono morti: `make -C labs/it/laboratorio stato` |
| Falliscono i controlli sui **numeri** (lab 7, 15, 19) | controlla integrità e data dello snapshot; se manca, il passo è SKIP, non PASS |

Durante la stesura del libro questa suite ha trovato errori veri; qualche esempio:

- il capitolo 6 dichiarava 3206 exit e 1616 relay con entrambi i flag; erano 3177 e 1615;
- il capitolo 7 diceva che i canali inattivi si chiudono dopo cinque minuti citando
  `KeepalivePeriod`, che è tutt'altro parametro: sono 3–4,5 minuti fra client e relay e
  45–75 fra relay;
- il capitolo 30 numerava i sottoprotocolli `FlowCtrl` a partire da zero, seguendo la
  documentazione di Arti, che su quel punto è sfasata di uno rispetto a torspec;
- il capitolo 31 chiedeva in un esercizio di verificare una cosa falsa sulle gambe di un
  tunnel Conflux;
- il capitolo 24 stampava conteggi il cui ordine cambiava a ogni esecuzione.

## Aggiungere un controllo

Ogni laboratorio con output pubblicati dovrebbe avere una verifica riproducibile. Si può aggiungere una funzione `labN()` a `scripts/verify_labs.py` che usa `controlla(nome, condizione, dettaglio)` e registrarla nel `main()`. Una buona verifica distingue PASS, FAIL e SKIP, controlla i codici di uscita e ripristina ciò che modifica.

Due trappole in cui sono caduto scrivendo i controlli, che valgono come avvertimento
generale: ho usato un metodo che non esiste (`Cella.codifica` invece della funzione
`codifica(cella, versione)`), e ho confrontato dei relay per nickname — ma nella rete
pubblica **151 nickname sono usati da più relay**, e i relay vanno confrontati per
identità. Un controllo sbagliato è peggio di nessun controllo: dà fiducia senza motivo.
