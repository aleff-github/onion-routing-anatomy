# Laboratorio 19 — Tempo alla prima compromissione

| | |
|---|---|
| **Capitolo** | 29 — Ricerca su Tor |
| **Serve la rete?** | non serve una rete Tor attiva per la simulazione; il primo download del consenso storico richiede HTTPS |
| **Prerequisiti** | Laboratori 7 e 15 |
| **Tempo** | 1–2 ore per scriverlo, tempo di esecuzione dipendente dalla macchina |
| **File** | `labs/it/codice/torlab/simulazione.py` |

## Che cosa dimostra

Che cosa fanno davvero i guard. Un avversario che controlla il 5 % della banda di guard
e il 5 % di quella di exit, senza guard persistenti, deanonimizza **metà dei client in
due settimane** e la quasi totalità in tre mesi. Con i guard persistenti, dopo sei mesi
è al 18,2 %.

I guard non riducono il rischio medio per circuito: lo **concentrano**. Per la maggior
parte degli utenti diventa quasi nullo; per i pochi che hanno scelto un guard ostile
diventa quasi certo.

## Preparazione

Come il [Laboratorio 7](Laboratorio-07-Percorsi.md): serve il consenso in
`labs/it/dati/collector/consensus-microdesc-2026-09-23-15`.

## Esecuzione

```bash
make -C labs/it data
export PYTHONPATH=labs/it/codice
python3 -m torlab.simulazione labs/it/dati/collector/consensus-microdesc-2026-09-23-15 0.05
```

Il secondo argomento è la quota di banda dell'avversario (qui il 5 %).

## Output atteso

```
avversario: 5% della banda di guard e 5% della banda di exit; 2000 client, 180 giorni, 20 circuiti/giorno
guard persistente     1g:  2.7%    7g:  4.5%   30g:  4.5%   90g:  9.3%  180g: 18.2%  mediana: None
guard per circuito    1g:  5.3%    7g: 29.2%   30g: 77.1%   90g: 99.1%  180g: 100.0%  mediana: 14
```

La simulazione è **deterministica** a parità di modulo, parametri, seme e consenso: questo è l'output del codice di `labs/it/codice` con il seme predefinito. Se i tuoi valori differiscono, controlla prima il consenso, quindi versione del codice e parametri. I numeri non sono stime di compromissione degli utenti Tor nel mondo reale.

Come leggerlo:

- **Riga 1, guard persistente.** La curva sale al 4,5 % nella prima settimana — sono i
  client che hanno estratto il guard ostile — e poi resta ferma: per gli altri, ogni nuovo
  circuito cambia exit ma non guard, e un exit ostile da solo non basta. Risale a ogni
  rotazione del guard, che per ciascun client cade in un giorno diverso, fino al 18,2 % a sei mesi. La
  cadenza è quella di un guard **confermato**: `GUARD_CONFIRMED_MIN_LIFETIME` = 60 giorni
  dalla conferma, meno la retrodatazione (fino a 12 giorni), cioè 48–60 giorni. I 120
  giorni di `GUARD_LIFETIME` sono il valore predefinito per i guard non confermati. Nella rete reale il client gestisce un insieme di guard campionati e confermati e le loro condizioni di raggiungibilità; questa simulazione sostituisce invece **un solo guard a intervalli prefissati**, e non riproduce l'intero algoritmo di selezione. Entrambi i limiti temporali possono essere modificati dai parametri di rete.
- **Riga 2, guard per circuito.** Ogni circuito è una lotteria nuova e le occasioni si
  sommano: mediana 14 giorni, 100 % a sei mesi.
- `mediana: None` sulla prima riga significa che meno della metà dei client è stata
  compromessa entro i 180 giorni simulati: la mediana non esiste nella finestra
  osservata. Non è un errore.

Provando altre quote:

| quota dell'avversario | compromessi a 180 g, con guard | senza guard |
|---:|---:|---:|
| 1 % | 4,0 % | 31,7 % |
| 5 % | 18,2 % | 100,0 % |

## Il modello, e i suoi limiti

2000 client, 180 giorni, 20 circuiti al giorno. Un client è compromesso il primo giorno
in cui un suo circuito ha **sia** guard **sia** exit dell'avversario.

Il modello ignora di proposito il relay intermedio, le famiglie, il vincolo delle /16,
i guard di riserva e i fallimenti di connessione. Serve a isolare un effetto, non a
predire il mondo. Un modello che li includesse tutti sarebbe più realistico e molto meno
istruttivo: non si capirebbe più da dove viene il risultato.

Per velocità i relay non si estraggono con `random.choices`, che ricalcolerebbe ogni
volta i pesi di novemila relay, ma con una ricerca binaria su pesi cumulati: milioni di estrazioni senza ricalcolare ogni volta la distribuzione. I tempi dipendono dall'hardware.

## Verifica automatica

Il controllo `lab19` in `make verifica-lab` fissa i due risultati principali: 18,2 % con i
guard persistenti e 100 % con mediana 14 senza.

## Problemi noti

Il consenso storico deve essere scaricato separatamente tramite `make -C labs/it data` (HTTPS): non è incluso nel repository. La sua assenza impedisce l'esecuzione. Lo script ne controlla l'intestazione, non le firme delle autorità.

## Da qui

- Il capitolo 13 spiega l'algoritmo dei guard e la differenza fra `GUARD_LIFETIME` (guard non confermati, 120 g) e `GUARD_CONFIRMED_MIN_LIFETIME` (guard confermati, 60 g), che è la durata che conta qui.
- Il capitolo 26 mostra l'attacco che questa simulazione modella
  ([Laboratorio 16](Laboratorio-16-Correlazione.md) lo esegue davvero, sul proprio traffico).
