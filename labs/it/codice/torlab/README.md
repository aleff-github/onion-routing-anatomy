# torlab — Client Tor didattico (edizione italiana)

Questo piccolo pacchetto Python accompagna i laboratori nella **rete Tor privata** del libro. **Non** è un client Tor di produzione e non garantisce anonimato. Non utilizzarlo per proteggere identità reali né indirizzare gli esperimenti interattivi verso relay pubblici. Per usi reali scegliere Tor Browser o Arti. La rete privata è descritta in [`../../laboratorio/`](../../laboratorio/README.md).

| Laboratorio | Capitolo | Moduli | Contenuto |
|---|---|---|---|
| 1 | 07 | `canale.py` | Canale TLS, VERSIONS, CERTS, NETINFO e verifiche di identità |
| 2 | 08 | `celle.py` | Codifica di celle fisse, variabili e relay |
| 3 | 09 | `ntor.py` | CREATE_FAST, ntor/ntor-v3, CREATE2/CREATED2 ed EXTEND2 |
| 4 | 10 | `cifratura.py`, `circuito.py` | Cifratura a strati, digest e costruzione dei circuiti |
| 5 | 11 | `stream.py` | BEGIN/DATA/END, SENDME e controllo di flusso |
| 6 | 12 | `directory.py` | Consenso, certificati, dati relay e microdescrittori |
| 7 | 13 | `percorso.py` | Selezione pesata di Guard/Middle/Exit |
| 8 | 14 | `onion.py` | Indirizzi onion v3, accecamento chiavi, HSDir e descrittori |
| 9 | 15 | `pow.py` | Soglia Blake2b: **simulazione senza Equi-X** |
| 12 | 20 | `traffico.py` | Lettura delle celle da una traccia TLS già decifrata |
| 15 | 24 | `metriche.py` | Statistiche di rete e stime illustrative degli utenti |
| 19 | 29 | `simulazione.py` | Modello di compromissione semplificato in stile TorPS |
| Appendice B | B | `conversione.py` | Conversione Montgomery/Edwards e certificati incrociati |
| Supporto | 19 | `laboratorio.py` | Identità e chiavi della rete privata |

### Esecuzione dei test

Dalla **radice della repository**, installate le dipendenze Python del progetto in un ambiente isolato:

```bash
PYTHONPATH=labs/it/codice python3 -m pytest -q labs/it/codice/torlab/test
```

In PowerShell:

```powershell
$env:PYTHONPATH = "labs/it/codice"
python -m pytest -q labs/it/codice/torlab/test
```

I comandi descrivono come riprodurre i test: **non attestano che siano stati superati**. I documenti crittografici e le catture sotto `test/dati/` vanno preservati byte per byte, non tradotti.

### Limiti del protocollo e fonti dei dati

- **Laboratorio 7:** il selettore usa i pesi del consenso (`bwweightscale`), gli identificatori dei relay e la distinzione IPv4 `/16`, ma non tutte le regole sulle famiglie, le policy di uscita, IPv6 o i Guard persistenti. Il consenso di laboratorio non sostituisce quello pubblico di una determinata data.
- **Laboratorio 8:** firme, cifratura e descrittori si studiano con fixture storiche. Il parser usa per impostazione predefinita `check_expiration=False` per questi dati; su dati attuali è necessario controllare autonomamente scadenza e autenticità della directory. Non sono implementati restricted discovery e tutte le verifiche degli introduction point.
- **Laboratorio 9:** `tentativi_necessari()` esamina **candidati casuali di 16 byte**, non soluzioni Equi-X. Dopo `max_attempts` (predefinito **10.000**) può generare `RuntimeError`. Superare la soglia Blake2b **non dimostra** un PoW Tor valido.
- **Laboratori 12, 15 e 19:** analisi del traffico, metriche e simulazioni richiedono le corrispondenti fonti storiche. Gli esempi sulla rete pubblica necessitano di dataset archiviati e verificati separatamente; le fixture private non li sostituiscono. La simulazione non garantisce l'anonimato.

Le API, i nomi dei campi e i vettori crittografici mantengono i byte originali. Test dinamici e verifiche di rete restano da eseguire.
