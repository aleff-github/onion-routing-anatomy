# Laboratorio 15 — Statistiche della rete da un consenso

| | |
|---|---|
| **Capitolo** | 24 — Misurare la rete: Tor Metrics |
| **Serve la rete?** | no (usa un consenso reale salvato su disco) |
| **Prerequisiti** | Laboratori 6 e 7 |
| **Tempo** | 1 ora per scriverlo, 1 minuto per rieseguirlo |
| **File** | `labs/it/codice/torlab/metriche.py` |

## Che cosa dimostra

Che le cifre pubblicate da [Tor Metrics](https://metrics.torproject.org/) si possono
ricavare da soli, partendo da un documento firmato e pubblico. E che la più citata di
tutte — il numero di utenti — non è un conteggio ma una **stima**: la rete non sa quanti
utenti ha, e non vuole saperlo.

## Preparazione

Come il [Laboratorio 7](Laboratorio-07-Percorsi.md): serve il consenso in
`labs/it/dati/collector/consensus-microdesc-2026-09-23-15`. Per verificarne anche le firme
serve in più il file dei certificati delle autorità:

```bash
curl -o labs/it/dati/collector/certs 'https://collector.torproject.org/recent/relay-descriptors/certs'
```

Se scarichi quel file da un browser, controlla che sia davvero il documento e non la
pagina HTML dell'indice: è un errore che mi è costato un'ora di firme «non valide».
La prima riga dev'essere `dir-key-certificate-version 3`.

## Esecuzione

Il modulo ha un'interfaccia a riga di comando:

```bash
export PYTHONPATH=labs/it/codice
python3 -m torlab.metriche labs/it/dati/collector/consensus-microdesc-2026-09-23-15
```

## Output atteso

```
relay: 9358
flag: {'Running': 9358, 'Valid': 9358, 'Fast': 8961, 'Stable': 8199, 'V2Dir': 7674,
       'Guard': 5306, 'HSDir': 4050, 'Exit': 3177, 'BadExit': 32, 'MiddleOnly': 28,
       'StaleDesc': 21, 'Authority': 10}
banda_totale: 198927900
quota_banda_exit: 0.3308947161257923
quota_banda_guard: 0.7010271560701139
versioni: [('Tor 0.4.9.12', 6027), ('Tor 0.4.9.11', 2520), ('Tor 0.4.9.9', 269), ...]
reti16: [('64.65', 771), ('192.42', 636), ('204.8', 598), ...]
```

Come leggerlo:

- I relay con flag `Exit` sono circa un terzo e portano circa un terzo della banda; i
  guard ne portano il 70 %. Le due quote si sovrappongono perché un relay può avere
  entrambi i flag: è lo squilibrio che i pesi di banda compensano
  ([Laboratorio 7](Laboratorio-07-Percorsi.md)).
- I relay con flag `Authority` sono **dieci**, ma le autorità che votano sono **nove**:
  la decima è `Serge`, l'autorità dei bridge, che ha il flag ma non partecipa al voto.
  È la domanda che si fa chiunque esegua questo laboratorio per la prima volta.
- `BadExit` (32) e `MiddleOnly` (28) sono decisioni delle autorità contro relay sospetti
  o mal configurati.
- Alcune /16 ospitano centinaia di relay: grandi operatori di exit. È la ragione del
  vincolo «un solo relay per /16 per circuito».

I conteggi sono ordinati per valore **e, a parità di valore, per nome**. Senza
quell'accorgimento l'ordine cambiava a ogni esecuzione, perché dipendeva da come Python
itera gli insiemi, e i numeri stampati nel libro non erano riproducibili.

## La stima degli utenti

```bash
python3 - <<'EOF'
from torlab.metriche import stima_utenti, togli_arrotondamento
print(stima_utenti(20_000_000, 0.6))     # 20 M di richieste di directory, copertura stimata del 60%
EOF
```

```
3333333
```

La stima complessiva segue Tor Metrics: client medi = richieste di directory
osservate ÷ frazione di copertura stimata ÷ 10 richieste giornaliere per client.
Per le stime *per paese*, Tor Metrics prima usa la quota dei conteggi
geografici per ripartire il totale delle richieste riuscite, riducendo
l'errore dell'arrotondamento. Nessun relay conta le persone: registra
richieste aggregate e si divide per un tasso ipotizzato.
Ogni passaggio aggiunge incertezza, ed è il motivo per cui il capitolo 1 parla di «tra
2,8 e 3,5 milioni» e non di un numero preciso.

## Verifica delle firme

```bash
python3 - <<'EOF'
from torlab.directory import analizza_consenso, analizza_certificati, verifica_consenso
c = analizza_consenso(open("labs/it/dati/collector/consensus-microdesc-2026-09-23-15").read())
cert = analizza_certificati(open("labs/it/dati/collector/certs").read())
print(verifica_consenso(c, cert, 9)[:2])
EOF
```

```
(9, 5)
```

Nove firme valide su nove autorità, e ne bastavano cinque. Se ottieni `(0, 5)`, il
problema quasi certamente non è la crittografia: è che stai firmando il testo sbagliato.
CollecTor antepone ai documenti una riga `@type ...` che **non fa parte** del documento
firmato; il calcolo deve partire da `network-status-version`.

## Verifica automatica

Il controllo `lab15` in `make verifica-lab` verifica il numero di relay, le due quote di
banda, la stima degli utenti e, se il file dei certificati è presente, le nove firme.

## Problemi noti

- `firme valide: (0, 5)` → vedi sopra: riga `@type` di CollecTor, oppure `labs/it/dati/collector/certs`
  è una pagina HTML.
- Con un consenso diverso da quello del 23 settembre 2026 tutti i numeri cambiano, e i
  controlli automatici falliscono: è previsto, quei controlli fissano i numeri stampati
  nel libro.
