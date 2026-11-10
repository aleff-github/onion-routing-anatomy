# Laboratorio 16 — Correlare il proprio traffico

| | |
|---|---|
| **Capitolo** | 26 — Attacchi alla rete |
| **Serve la rete?** | sì |
| **Prerequisiti** | la rete avviata |
| **Tempo** | 1–2 ore |
| **File** | `labs/it/laboratorio/correlazione.py` |

> **Solo sul proprio traffico.** Questo laboratorio esegue l'attacco che Tor non può
> impedire, su sei client che siamo noi stessi, dentro la nostra rete. Farlo su traffico
> altrui è sorveglianza, e il capitolo 25 spiega che cosa comporta.

## Che cosa dimostra

Che la correlazione da estremo a estremo **funziona**, e che non serve nulla di
sofisticato: bastano i tempi. Sei client inviano dati attraverso la rete privata con
ritmi casuali diversi; un osservatore all'ingresso annota quando ciascun client scrive,
un osservatore all'uscita quando i byte arrivano. Confrontando le due serie temporali si
ricostruisce chi parla con chi.

È il limite fondamentale di Tor, dichiarato fin dall'articolo del 2004: la rete non
protegge da chi vede **entrambi** i capi.

## Preparazione

```bash
make -C labs/it/laboratorio avvia
```

Lo script gira dentro il container e usa la porta SOCKS del client (9008):

```bash
docker exec -w /tmp torlibro-rete python3 /lab/correlazione.py 3
```

L'argomento è il **seme** del generatore casuale, così che una prova si possa ripetere
identica. La durata è fissata nello script (`DURATA = 20` secondi di traffico, in bin da
0,25 s); l'esecuzione completa richiede una quarantina di secondi.

## Output atteso

```
client 0: +0.24 -0.04 +0.09 +0.86 +0.00 -0.04  -> uscita 3 OK
client 2: -0.03 +0.85 +0.35 -0.07 +0.13 -0.05  -> uscita 1 OK
client 5: +0.87 -0.01 +0.27 +0.26 +0.05 +0.15  -> uscita 0 OK
client 4: +0.09 +0.32 +0.85 -0.07 +0.02 +0.10  -> uscita 2 OK
client 1: +0.24 -0.07 +0.19 +0.08 -0.03 +0.72  -> uscita 5 OK
client 3: +0.17 +0.13 +0.04 +0.13 +0.70 +0.09  -> uscita 4 OK
abbinamenti corretti: 6/6
```

Come leggerlo:

- Ogni riga è un client, e i sei numeri sono la **correlazione** fra la sua serie
  temporale all'ingresso e ciascuna delle sei serie osservate all'uscita.
- Il valore giusto salta all'occhio: **0,7–0,9** contro valori vicini a zero per tutti
  gli altri. Non c'è bisogno di una soglia sofisticata; la differenza è di un ordine di
  grandezza.
- `abbinamenti corretti: 6/6` è la verità nota **solo a noi**, che abbiamo costruito
  l'esperimento: l'attacco non la usa per abbinare, la usa solo chi valuta il risultato.
- Talvolta esce 5/6: due client con ritmi simili si confondono. Il controllo automatico
  accetta 5/6 o 6/6.

Il segnale è così forte perché la rete di laboratorio non ha traffico di copertura: sei
client e nient'altro. Sulla rete vera, con milioni di flussi, la correlazione è più
difficile ma non impossibile — ed è più facile quanto più l'avversario osserva.

## Che cosa non dimostra

Che chiunque possa fare questo attacco. Servono **entrambi** i capi: qui li abbiamo per
costruzione, nella realtà occorre osservare sia l'ingresso del client sia l'uscita verso
la destinazione. È il motivo per cui esistono i guard
([Laboratorio 19](Laboratorio-19-Simulazione.md)): non impediscono la correlazione, ma
riducono la probabilità che un avversario si trovi nella posizione giusta.

## Verifica automatica

Il controllo `lab16` verifica che gli abbinamenti corretti siano almeno 5 su 6.

## Problemi noti

| Sintomo | Causa |
|---|---|
| Meno di 5 abbinamenti | rete molto carica: riprova, eventualmente con un altro seme |
| Lo script si blocca all'avvio | la porta SOCKS 9008 non risponde: il client `008c` non è partito |
| `Address already in use` | la porta del server di prova (8095) è occupata |
