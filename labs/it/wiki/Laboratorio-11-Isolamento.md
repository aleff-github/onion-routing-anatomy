# Laboratorio 11 — L'isolamento degli stream dal vivo

| | |
|---|---|
| **Capitolo** | 18 — Controllare tor: la porta di controllo e Stem |
| **Serve la rete?** | sì |
| **Prerequisiti** | la rete avviata; `stem` (già dentro il container) |
| **Tempo** | 1 ora |
| **File** | `labs/it/laboratorio/isolamento.py` |

## Che cosa dimostra

Che tor non mette tutto il traffico sullo stesso circuito: separa gli stream in base
alle **credenziali SOCKS** con cui l'applicazione si presenta. È uno dei meccanismi su cui si
regge la separazione per sito di Tor Browser: `IsolateSOCKSAuth` impedisce a
stream con credenziali diverse di condividere un circuito. **Non equivale a
separare automaticamente ogni scheda** (due schede dello stesso sito
possono condividere il medesimo contesto), né garantisce relay di uscita
diversi: due circuiti separati possono selezionare lo stesso exit.

E dimostra anche una cosa che il libro spiega e che in laboratorio si vede benissimo:
con Conflux attivo, ciò che viene isolato non è il singolo circuito ma il **tunnel**, che
è una coppia di circuiti collegati.

## Preparazione

```bash
make -C labs/it/laboratorio avvia
# Directory temporanea sacrificabile: NON servire la radice del repository,
# che può contenere net/ con chiavi di identità e cookie dei nodi.
WEBROOT=$(mktemp -d /tmp/torlibro-lab11.XXXXXX)
echo "pagina di prova" > "$WEBROOT/index.html"
python3 -m http.server 8080 --bind 127.0.0.1 --directory "$WEBROOT" &
WEB_PID=$!
```

Dopo aver concluso le richieste, **nella stessa shell**, chiudi il server con
`kill "$WEB_PID"` e rimuovi soltanto la cartella temporanea `"$WEBROOT"`
dopo aver verificato il percorso. La porta rimane su localhost, ma con
`--network host` il container condivide la rete dell'host: questo non
costituisce un isolamento della rete privata dalla macchina.

Lo script gira **dentro il container**, perché usa `stem` per parlare con la porta di
controllo del client:

```bash
docker exec -w /tmp torlibro-rete python3 /lab/isolamento.py
```

## Output atteso

```
credenziali sito-a.example  -> conflux 90EFE5BD       ['test004r', 'test005r', 'test007e']
credenziali sito-a.example  -> conflux 90EFE5BD       ['test004r', 'test005r', 'test007e']
credenziali sito-b.example  -> conflux A608C1C1       ['test004r', 'test006e', 'test007e']
credenziali -               -> conflux 2FED7F85       ['test004r', 'test003r', 'test007e']
(NEWNYM rinviato di 6 s)
dopo NEWNYM, sito-a.example  -> conflux BA715C26
```

Come leggerlo:

- Le prime due righe usano le **stesse** credenziali e ottengono lo **stesso** tunnel:
  è l'isolamento che funziona al contrario, cioè che non separa ciò che non va separato.
- Le righe 2–4 hanno credenziali diverse e tunnel diversi.
- Dopo `NEWNYM` le stesse credenziali di prima ottengono un tunnel **nuovo**: è ciò che
  fa il pulsante «Nuova identità».
- Gli identificatori `conflux XXXXXXXX` sono i `CONFLUX_ID`. Gli elenchi di relay sono
  quelli di una delle due gambe.

## Le tre trappole, tutte trovate sul campo

Questo laboratorio falliva circa una volta su quattro. Le cause erano tre, e insieme:

1. **tor apre stream propri.** Le richieste di directory generano eventi `STREAM` come
   tutti gli altri: contandoli, il conteggio è falsato. Lo script filtra per destinazione
   e prende l'ultimo evento.
2. **`NEWNYM` è limitato a uno ogni 10 secondi** (`MAX_SIGNEWNYM_RATE`). Un segnale
   inviato troppo presto viene **rinviato**, non ignorato: arrivava a metà della prova
   successiva e mescolava i risultati. Lo script ora aspetta, e stampa l'attesa.
3. **Conflux.** I circuiti sono accoppiati (`CONFLUX_LINKED`): l'isolamento separa i
   tunnel, non le gambe. Guardando i singoli circuiti sembrava che l'isolamento non
   funzionasse.

Resta una variabilità residua quando la rete è molto sollecitata: su una rete di tre
relay tor può preferire un tunnel appena costruito. Il controllo automatico lo mette in
conto e ripete fino a tre volte. Non è un difetto nascosto sotto il tappeto: è una
proprietà di una rete con pochissimi nodi, e il capitolo 18 lo dice.

## Verifica automatica

Il controllo `lab11` verifica le tre proprietà: stesse credenziali → stesso tunnel,
credenziali diverse → tunnel diversi, `NEWNYM` → tunnel nuovo.

## Problemi noti

| Sintomo | Causa |
|---|---|
| Lo script non trova stream | manca il server sulla 8080, oppure la destinazione nello script non corrisponde |
| Due credenziali diverse finiscono sullo stesso tunnel | capita raramente su una rete così piccola: riesegui |
| `SocketError` sulla porta di controllo | stai eseguendo lo script sull'host invece che nel container |
