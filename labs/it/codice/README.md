# torlab — il client Tor didattico (ambiente italiano)

Il pacchetto Python `torlab` accompagna i laboratori del libro *Anatomia di Tor*. Implementa una parte del protocollo Tor a scopo didattico, usando esclusivamente la rete sperimentale privata descritta in [`../README.md`](../README.md). Non è un client completo né uno strumento di anonimato da usare su Internet.

## Prove previste

Dalla **radice della repository**, con Python 3.11+, `pytest` e `cryptography` installati:

```bash
PYTHONPATH=labs/it/codice python3 -m pytest -q labs/it/codice/torlab/test
make -C labs/it test
```

Entrambi i comandi sono riferiti al codice localizzato in `labs/it/codice/`. Questi sono comandi per le prove unitarie locali, **non** una certificazione dell'interoperabilità con la rete Tor; la loro esecuzione non è attestata da questa guida.

## Moduli del pacchetto

| Modulo | Lab | Funzione |
|---|---:|---|
| `canale.py` | 1 | collegamento TLS, celle di avvio e identità del relay |
| `celle.py` | 2 | celle fisse, variabili e messaggi relay |
| `ntor.py` | 3 | handshake ntor e ntor-v3 |
| `cifratura.py`, `circuito.py` | 4 | cifratura a strati e circuiti |
| `stream.py` | 5 | stream e SENDME |
| `directory.py` | 6 | consenso, certificati e microdescrittori |
| `percorso.py` | 7 | selezione pesata dei percorsi |
| `onion.py` | 8 | indirizzi e descrittori onion v3 |
| `pow.py` | 9 | filtro Blake2b con soluzioni Equi-X **simulate** |
| `traffico.py` | 12 | interpretazione di una cattura TLS decifrata |
| `metriche.py` | 15 | statistiche del consenso |
| `simulazione.py` | 19 | simulazione della compromissione |
| `conversione.py` | App. B | conversione di chiavi e certificazione incrociata |
| `laboratorio.py` | supporto | nodi e porte della rete privata |

Gli altri laboratori hanno, quando previsto, script separati in `../laboratorio/`. I test usano anche dati e vettori tecnici che devono mantenere i byte originali. Il modulo `pow.py` **non implementa Equi-X**: i suoi tentativi sono simulati e studiano il livello Blake2b.

## Limiti e sicurezza

Il client non implementa tutte le difese, il padding, la rotazione dei circuiti né il controllo completo della congestione. Non usarlo per traffico reale, attività sensibili o protezione dell'identità: per tali scopi utilizzare software Tor o Arti ufficiale, aggiornato e correttamente configurato. La rete privata dei laboratori non è un sostituto di un ambiente isolato dal sistema host.