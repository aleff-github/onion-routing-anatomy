# Laboratorio 9 — Provocare le difese anti-DoS

| | |
|---|---|
| **Capitolo** | 15 — Attacchi DoS e difese |
| **Serve la rete?** | sì, con l'immagine compilata `--enable-gpl` |
| **Prerequisiti** | Laboratori 1–8 |
| **Tempo** | 2 ore |
| **File** | `labs/it/codice/torlab/pow.py` |

> **Solo sulla tua rete.** Questo laboratorio genera traffico anomalo di proposito. Farlo
> contro relay o servizi reali è un attacco: danneggia altre persone e, in molti
> ordinamenti, è un reato (capitolo 25).

## Che cosa dimostra

**Ambito del risultato storico:** nove circuiti accettati su 30 con burst impostato a 10 descrivono una prova su una versione e una configurazione specifica di Tor, **non un'invariante del protocollo**. Il secchio si ricarica nel tempo e contano anche le connessioni e l'eventuale blocco precedente dell'IP. Tutto va riprodotto **solo su una rete Chutney privata e sacrificabile**.

Che le difese anti-DoS di un relay si possono osservare dall'esterno, e che si comportano
in modo leggermente diverso da come le si immagina leggendo la documentazione. In
particolare: con un burst di 10 passano **9** circuiti, non 10, e le connessioni da
127.0.0.1 **non** sono esenti.

E poi la prova di lavoro degli onion service: come si attiva, che cosa pubblica il
descrittore, e perché lo sforzo richiesto cresce in modo lineare.

## Preparazione

Se l'immagine non esiste ancora, eseguire prima `make -C labs/it/laboratorio immagine`, poi `make -C labs/it/laboratorio avvia`. `avvia` non costruisce automaticamente Docker. Per le funzionalità PoW occorre controllare sia il modulo opzionale sia la compilazione con `--enable-gpl`.

```bash
make -C labs/it/laboratorio avvia
export PYTHONPATH=labs/it/codice
```

L'immagine dev'essere compilata con `--enable-gpl`, altrimenti il modulo della prova di
lavoro non c'è. Il `Dockerfile` del repository lo fa già:

```bash
docker run --rm torlibro-lab:latest tor --list-modules
docker run --rm torlibro-lab:latest tor --version
```

## Parte 1 — il limite sulla creazione di circuiti

**Precauzione:** il ricaricamento della configurazione deve raggiungere soltanto il PID del relay `003r`, ricavato da `/lab/net/nodes/003r/pid` nel container di laboratorio. Evitare `pkill -f` su una sottostringa del comando. Il `finally` ripristina il file, ma un errore di reload o un'interruzione forzata può lasciare lo stato del processo incoerente: verificare sempre `torrc` e log dopo l'esperimento.

Aggiungiamo al `torrc` di `003r` limiti molto bassi, gli facciamo rileggere la
configurazione con `HUP`, e chiediamo 30 circuiti di fila con `CREATE_FAST`. Il torrc
viene sempre ripristinato alla fine.

```bash
python3 - <<'EOF'
import subprocess, time
from collections import Counter
from torlab.canale import apri_canale
from torlab.celle import Cella, Comando
from torlab.laboratorio import relay, NODI
from torlab.ntor import create_fast_client

torrc = NODI / "003r" / "torrc"
originale = torrc.read_text()
hup = ["docker", "exec", "torlibro-rete", "sh", "-c",
       "kill -HUP $(cat /lab/net/nodes/003r/pid)"]
try:
    torrc.write_text(originale + """
DoSCircuitCreationEnabled 1
DoSCircuitCreationMinConnections 2
DoSCircuitCreationRate 1
DoSCircuitCreationBurst 10
DoSCircuitCreationDefenseType 2
DoSCircuitCreationDefenseTimePeriod 60 seconds
""")
    subprocess.run(hup, check=True); time.sleep(2)
    g = relay("003r")
    for origine, n_canali in (("127.0.0.2", 2), ("127.0.0.3", 1), ("127.0.0.1", 2)):
        canali = [apri_canale("127.0.0.1", g.porta, identita_attesa=g.id_ed, origine=origine)
                  for _ in range(n_canali)]
        esiti, motivi, primo = [], Counter(), None
        for i in range(30):
            x, corpo = create_fast_client()
            canali[0].invia(Cella(0x80000100 + i, Comando.CREATE_FAST, corpo))
            r = canali[0].ricevi()
            while r.comando in (Comando.PADDING, Comando.VPADDING):
                r = canali[0].ricevi()
            ok = r.comando == Comando.CREATED_FAST
            esiti.append(ok)
            if not ok:
                motivi[r.corpo[0]] += 1
                primo = primo or i + 1
        m = ", ".join(f"DESTROY({k})" for k in motivi)
        print(f"origine {origine}, {n_canali} {'canale' if n_canali == 1 else 'canali'}: {esiti.count(True)} ok, "
              f"{30-esiti.count(True)} {m or '-'}; primo rifiuto al n. {primo}")
finally:
    torrc.write_text(originale)
    subprocess.run(hup)
EOF
```

```
origine 127.0.0.2, 2 canali: 9 ok, 21 DESTROY(5); primo rifiuto al n. 10
origine 127.0.0.3, 1 canale: 30 ok, 0 -; primo rifiuto al n. None
origine 127.0.0.1, 2 canali: 9 ok, 21 DESTROY(5); primo rifiuto al n. 10
```

**Uscita storica illustrativa:** tempi di handshake, token che si ricaricano e IP già marcati possono cambiare il conteggio: registrare le risposte osservate anziché considerare `9` un requisito universale.

Tre cose da notare:

1. Il rifiuto è un **`DESTROY` di motivo 5**, `RESOURCELIMIT`.
2. Con un burst di 10 passano **9** circuiti. `cc_has_exhausted_circuits`
   (`src/core/or/dos.c`) marca il client appena il secchio arriva a zero, quindi la
   decima richiesta è già respinta. Leggendo solo la documentazione si direbbe 10.
3. Con **un solo canale non scatta nulla**: la difesa richiede almeno
   `MinConnections` connessioni contemporanee, per non punire un client normale, che
   verso il proprio guard ne tiene di solito una.

Avevo previsto che le connessioni da 127.0.0.1 — l'indirizzo di tutti i relay del
laboratorio — fossero esenti. L'esperimento ha smentito la previsione, e `dos.c` conferma
che un'esenzione del genere, per i circuiti, non esiste.

Gli indirizzi di origine diversi servono a non riusare un contatore già marcato: un
indirizzo bloccato resta tale per tutto il periodo di difesa, 60 secondi.

## Parte 2 — la prova di lavoro dell'onion service

**Modifica persistente:** conservare una copia del `torrc` originale di `009h`, inviare HUP al solo PID del servizio dopo la modifica e, terminato il laboratorio, **ripristinare il file e inviare nuovamente HUP**. Per gli esperimenti confinati a questa rete privata è preferibile ricreare la topologia in caso di ripristino incerto.

La riga `pow-params` riportata sotto è storica: cambiano seme, ora UTC di scadenza e sforzo suggerito. Lo sforzo zero indica soltanto che il servizio, in quel momento, non pretende lavoro aggiuntivo: **non dimostra che la coda sia vuota**. La scadenza del seme viene scelta nella finestra raccomandata di 105–120 minuti.

```bash
# aggiungere al torrc di 009h, dopo le righe HiddenService...
HiddenServicePoWDefensesEnabled 1
# poi: docker exec torlibro-rete sh -c 'kill -HUP $(cat /lab/net/nodes/009h/pid)'
```

Dopo il `HUP` il servizio pubblica un descrittore nuovo. Scaricandolo con il
[Laboratorio 8](Laboratorio-08-Onion.md), nel secondo strato compare:

```
pow-params v1 9qe8kJUi30tgcAlInd5a+trFeVl1yjQtPRb0F4u9C7Y= 0 2026-09-24T17:56:10
```

Schema `v1`, il seme in base64, uno sforzo suggerito di **zero** — non veniva richiesto lavoro aggiuntivo in quel momento — e la scadenza del seme, circa un'ora e cinquantacinque minuti
dopo la pubblicazione, dentro la finestra di 105–120 minuti prevista.

Aspetta una quarantina di secondi dopo il `HUP`: il descrittore nuovo dev'essere
pubblicato e propagato.

## Parte 3 — lo sforzo è lineare

**Questa è solo una simulazione Monte Carlo del controllo Blake2b, non Equi-X.** I sedici byte casuali usati come `soluzione` non formano una prova Equi-X valida; non si ricava alcuna misura attendibile del costo reale del puzzle. Nella procedura v1 completa occorre superare sia Equi-X sia il vincolo Blake2b. Per un valore `R` casuale e uniforme su 32 bit, la probabilità di superare il solo controllo Blake2b è circa `1/sforzo` per sforzi positivi.

Equi-X non esiste in Python, ma il livello che rende lo sforzo lineare e verificabile è
Blake2b, e quello si studia benissimo simulando le soluzioni con byte casuali, che ai
fini del test hanno la stessa distribuzione.

```bash
python3 - <<'EOF'
import os, statistics
from torlab.pow import tentativi_necessari
id_servizio, seme = os.urandom(32), os.urandom(32)
for sforzo in (1, 10, 100, 1000):
    prove = [tentativi_necessari(sforzo, id_servizio, seme) for _ in range(400)]
    print(f"sforzo {sforzo:>4}: {statistics.mean(prove):.1f} tentativi")
EOF
```

```
sforzo    1: 1.0 tentativi
sforzo   10: 10.5 tentativi
sforzo  100: 90.0 tentativi
sforzo 1000: 1027.7 tentativi
```

I numeri **oscillano a ogni esecuzione** — le soluzioni sono casuali — ma la proporzione
resta: i tentativi crescono linearmente con lo sforzo.

Un dettaglio facile da sbagliare, che la specifica sottolinea: `blake2b` con
`digest_size=4` **non** equivale ai primi 4 byte di un Blake2b da 64, perché la lunghezza
dell'uscita entra nello stato iniziale della funzione.

## Verifica automatica

Il verificatore italiano `lab9` utilizza due canali e un indirizzo di origine loopback nuovo; controlla l'esito storico dei nove circuiti. La wiki aggiunge un confronto fra uno e due canali e la dimostrazione PoW. Il test offline `labs/it/codice/torlab/test/test_pow.py` verifica il limite Blake2b e alcune medie statistiche su 300 campioni con sforzi 10 e 40. **Non** verifica né l'antiflood di rete né Equi-X.

Per eseguire il test offline:

```bash
PYTHONPATH=labs/it/codice python3 -m pytest -q labs/it/codice/torlab/test/test_pow.py
```

Il controllo `lab9` copre la Parte 1 (9 circuiti accettati su 30). Le Parti 2 e 3 non
sono nella suite automatica: la 2 modifica la configurazione dell'onion service e
richiede l'attesa di una pubblicazione, la 3 è statistica e non ha un valore atteso
esatto.

## Problemi noti

| Sintomo | Causa |
|---|---|
| Tutti e 30 i circuiti rifiutati subito | l'indirizzo di origine è ancora marcato da una prova precedente: aspetta 60 secondi o cambia origine |
| Nessun rifiuto con due canali | il `HUP` non è arrivato: controlla il `notice.log` di `003r` |
| Nessuna riga `pow-params` nel descrittore | l'immagine non è compilata con `--enable-gpl`, oppure non hai atteso la nuova pubblicazione |
