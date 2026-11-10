# Laboratorio 17 — Il limite delle celle RELAY_EARLY

| | |
|---|---|
| **Capitolo** | 27 — Casi reali: quando la rete è stata attaccata |
| **Serve la rete?** | sì |
| **Prerequisiti** | Laboratori 1–4 |
| **Tempo** | 1 ora |
| **File** | `labs/it/laboratorio/relay_early.py` |

## Che cosa dimostra

Il limite di otto celle `RELAY_EARLY` inviate dal client alla rete esisteva **già prima del 2014**: la nona cella distrugge il circuito. Dopo l'attacco del 2014 fu introdotto, separatamente, il rifiuto delle celle `RELAY_EARLY` inattese dirette **verso il client**.

Nel 2014 un gruppo di relay ostili usò proprio quelle celle come **canale nascosto**:
alternando `RELAY` e `RELAY_EARLY` secondo uno schema, un HSDir malevolo trasmetteva un segnale verso un guard complice attraverso il circuito. Il guard poteva così collegare l'IP del client alla richiesta del descrittore di un onion service, **non dimostrare che il sito fosse stato visitato**. La correzione del 2014 respinse le celle premature in direzione del client; la soglia di otto in direzione della rete era precedente.

## Preparazione

```bash
make -C labs/it/laboratorio avvia
export PYTHONPATH=labs/it/codice
```

## Esecuzione

```bash
python3 labs/it/laboratorio/relay_early.py 8 9
```

Gli argomenti sono il numero di celle `RELAY_EARLY` da inviare in ciascuna prova.

## Output atteso

```
8 celle RELAY_EARLY -> CONNECTED
9 celle RELAY_EARLY -> circuito distrutto, motivo 1
```

Come leggerlo:

- Con **otto** celle il circuito è ancora vivo: la richiesta successiva riceve un
  `CONNECTED`.
- Con **nove** il relay manda un `DESTROY` di motivo **1**, `PROTOCOL`. Non un avviso,
  non un rifiuto della singola cella: il circuito intero.
- Il limite è 8 perché servono per le estensioni: un circuito di tre salti ne usa due
  (`EXTEND2`), e il margine copre i casi con più salti, come i circuiti verso un onion
  service.

Lo script invia le celle **scavalcando il proprio client**, che si fermerebbe a otto da
solo: costruisce il corpo cifrato e lo spedisce come cella `RELAY_EARLY` a mano. È un
esperimento che si può fare solo avendo scritto il client da sé — e solo sulla propria
rete.

## Perché un canale nascosto è così pericoloso

Non serve decifrare nulla. Il relay di ingresso conosce l'utente ma non la destinazione;
quello di uscita conosce la destinazione ma non l'utente. Un canale che permetta ai due
di scambiarsi un identificatore unisce le due metà, e l'anonimato sparisce — senza
rompere un solo algoritmo crittografico.

È la ragione per cui il protocollo cerca di eliminare ogni campo che un relay possa
modificare per far passare informazione: ogni bit osservabile e controllabile è un
canale potenziale.

## Verifica automatica

Il controllo `lab17` verifica entrambe le righe.

## Problemi noti

| Sintomo | Causa |
|---|---|
| Anche con 8 celle il circuito muore | il contatore include le celle usate per l'estensione: con un circuito di più salti il margine si riduce |
| `ErroreCircuito` fin dalla prima cella | il circuito non si è costruito: controlla che la rete sia avviata |
