# Wiki dei laboratori

Questa wiki accompagna il libro *Anatomia di Tor. Il protocollo dell'anonimato, byte per byte* e descrive **venti laboratori**: obiettivi, prerequisiti, comandi, output di riferimento e problemi noti. I frammenti di codice nelle pagine sono semplificati per la lettura e omettono parte dei controlli di validità: il riferimento è il codice in `labs/it/codice` e `labs/it/laboratorio`.

Il libro spiega *perché*. Questa wiki serve a *farlo funzionare*.

> Gli esperimenti che usano traffico di rete si svolgono in una rete Tor privata e non prendono di mira utenti della rete pubblica. Il laboratorio 2 è offline; i laboratori 7, 15 e 19 elaborano documenti storici del Tor Project, da acquisire separatamente per riprodurre i risultati numerici.

## Prima volta qui

1. [Installazione](Installazione.md) — che cosa serve e come si prepara, da zero.
2. [La rete di laboratorio](Rete-di-laboratorio.md) — topologia, porte, comandi, come si
   riavvia quando si pianta.
3. [Verifica automatica](Verifica-automatica.md) — test Python, verifiche Chutney sulla rete privata e script specifici, con prerequisiti diversi.
4. [Risoluzione dei problemi](Risoluzione-dei-problemi.md) — l'elenco dei guasti reali e
   della loro causa.

## I venti laboratori

| Lab | Cap. | Titolo | Rete |
|----:|-----:|---|:--:|
| 1 | 7 | [Aprire un canale verificato](Laboratorio-01-Canale.md) | sì |
| 2 | 8 | [Codificare e decodificare celle](Laboratorio-02-Celle.md) | no |
| 3 | 9 | [Handshake di circuito: ntor e ntor-v3](Laboratorio-03-Handshake.md) | sì |
| 4 | 10 | [Cifratura a strati e circuito di tre salti](Laboratorio-04-Cifratura.md) | sì |
| 5 | 11 | [Scaricare un file: stream, finestre e SENDME](Laboratorio-05-Stream.md) | sì |
| 6 | 12 | [Scaricare e verificare il consenso](Laboratorio-06-Directory.md) | sì |
| 7 | 13 | [Selezione pesata dei percorsi](Laboratorio-07-Percorsi.md) | no |
| 8 | 14 | [Trovare e leggere un descrittore onion](Laboratorio-08-Onion.md) | sì |
| 9 | 15 | [Provocare le difese anti-DoS](Laboratorio-09-DoS.md) | sì |
| 10 | 16 | [Un bridge obfs4 e lo sguardo del censore](Laboratorio-10-Bridge.md) | rete a parte |
| 11 | 18 | [L'isolamento degli stream dal vivo](Laboratorio-11-Isolamento.md) | sì |
| 12 | 20 | [Le celle dentro il TLS](Laboratorio-12-Traffico.md) | sì |
| 13 | 21 | [Un onion service con scoperta ristretta](Laboratorio-13-Scoperta-ristretta.md) | sì |
| 14 | 22 | [Una politica di uscita alla prova](Laboratorio-14-Politica-di-uscita.md) | sì |
| 15 | 24 | [Statistiche della rete da un consenso](Laboratorio-15-Metriche.md) | no |
| 16 | 26 | [Correlare il proprio traffico](Laboratorio-16-Correlazione.md) | sì |
| 17 | 27 | [Il limite delle celle RELAY_EARLY](Laboratorio-17-Relay-early.md) | sì |
| 18 | 28 | [tor riconosce la fuga DNS](Laboratorio-18-Fuga-DNS.md) | sì |
| 19 | 29 | [Tempo alla prima compromissione](Laboratorio-19-Simulazione.md) | no |
| 20 | 30 | [Arti nella rete privata](Laboratorio-20-Arti.md) | sì |

I laboratori della Parte II (1–10) illustrano `labs/it/codice/torlab` un pezzo alla volta e
vanno fatti in ordine: ognuno usa i moduli dei precedenti. Quelli successivi sono
indipendenti tra loro.

## Come è fatta ogni pagina

Che cosa dimostra il laboratorio · preparazione · comandi esatti · output atteso, con la
spiegazione di come leggerlo · verifica automatica · problemi noti.

I laboratori 1–8, quelli che costruiscono il client, hanno in più una sezione **«Il codice,
in dettaglio»**: ogni funzione spiegata pezzo per pezzo, con il perché delle scelte, le
trappole in cui si cade scrivendola da soli, e una tabella finale che dice da quale punto
della specifica viene ciascuna regola. È la parte che nel libro non c'è: il libro spiega il
protocollo, qui si spiega l'implementazione.

Gli output riportati vengono dalle esecuzioni di riferimento dei laboratori con tor 0.4.9.13 sulla rete privata del libro. Chiavi, indirizzi e tempi cambiano a ogni esecuzione; i dati numerici dei laboratori 7, 15 e 19 richiedono gli stessi ingressi storici. In caso di differenze nella struttura del protocollo, consulta [Risoluzione dei problemi](Risoluzione-dei-problemi.md) e riesegui i controlli pertinenti.
