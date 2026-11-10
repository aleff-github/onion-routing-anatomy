# Laboratorio 14 — Una politica di uscita alla prova

| | |
|---|---|
| **Capitolo** | 22 — Gestire un relay |
| **Serve la rete?** | sì |
| **Prerequisiti** | Laboratori 1–5 |
| **Tempo** | 1 ora |
| **File** | `labs/it/laboratorio/politica_uscita.py` |

## Che cosa dimostra

Che cosa succede, dal punto di vista del client, quando un exit rifiuta una
destinazione: il messaggio `END` che riceve, con quale motivo, e che cosa quel motivo
rivela. Tre destinazioni, tre esiti diversi, tutti sullo stesso exit.

E, di passaggio, un piccolo difetto di tor 0.4.9.13 che è emerso proprio da qui.

## Preparazione

```bash
make -C labs/it/laboratorio avvia
export PYTHONPATH=labs/it/codice
```

Lo script aggiunge al `torrc` dell'exit `006e` una regola che rifiuta **una sola porta**,
inserita **prima** delle regole esistenti (vince la prima che corrisponde), avvia i
server di prova che gli servono, esegue tre tentativi e **ripristina sempre** il torrc.

## Esecuzione

```bash
python3 labs/it/laboratorio/politica_uscita.py
```

## Output atteso

```
127.0.0.1:8080 -> END motivo=EXITPOLICY indirizzo=127.0.0.1 TTL=1800
127.0.0.1:8081 -> CONNECTED
127.0.0.1:9999 -> END motivo=MISC
```

Come leggerlo:

- **8080, `EXITPOLICY`**: la porta rifiutata dalla regola appena aggiunta. Il corpo del
  messaggio contiene anche l'indirizzo e un TTL di 1800 secondi: servono al client per
  capire che quell'exit non va bene *per quella destinazione* e sceglierne un altro,
  senza rifare la risoluzione.
- **8081, `CONNECTED`**: la politica lascia passare, e il server risponde.
- **9999, `MISC`**: nessun server in ascolto. Qui ci si aspetterebbe
  `CONNECTREFUSED`.

## Il difetto di tor 0.4.9.13

`MISC` invece di `CONNECTREFUSED` non è un errore del laboratorio. È andata così:

tor registra correttamente `ECONNREFUSED` nel proprio log — l'ha letto da
`getsockopt(SO_ERROR)` — ma poi `connection_edge_end_errno()` **ricalcola** il motivo da
`tor_socket_errno`, che su Unix è la macro `(errno)`. A quel punto `errno` vale ancora
`EINPROGRESS` (115), che non corrisponde a nessun caso previsto, e si finisce nel ramo
predefinito: `MISC`.

L'effetto pratico è modesto — il client capisce comunque che la connessione è fallita —
ma l'informazione «connessione rifiutata», che il client userebbe per non insistere, va
persa. È un difetto minore che varrebbe la pena segnalare al Tor Project.

Questo è anche il motivo per cui il valore atteso nel controllo automatico è `MISC` e non
`CONNECTREFUSED`: documenta il comportamento **reale** della versione di riferimento, non
quello ideale. Se una versione futura lo correggesse, il controllo fallirebbe, ed è
esattamente ciò che si vuole.

## Perché tre salti e non uno

Lo script costruisce un circuito di **tre** salti anche se, per parlare con l'exit, uno
basterebbe. Con un circuito di un salto tutte e tre le prove rispondevano
`END TORPROTOCOL`: un exit **rifiuta di uscire** da un circuito di un solo salto, perché
sarebbe un proxy aperto a disposizione di chiunque. Ci ho perso un po' di tempo prima di
accorgermene.

## Verifica automatica

Il controllo `lab14` verifica tutte e tre le righe, motivo per motivo.

## Problemi noti

| Sintomo | Causa |
|---|---|
| Tutte le prove danno `END TORPROTOCOL` | circuito di un salto (vedi sopra) |
| `8081 -> END motivo=EXITPOLICY` | la regola è finita **dopo** le altre, oppure hai lasciato una modifica di una prova precedente: controlla il torrc di `006e` |
| `assert: nessuna riga ExitPolicy nel torrc di 006e` | non stai usando la rete `libro`, oppure il nodo `006e` non è un exit |
