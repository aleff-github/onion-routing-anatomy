# Dati pubblici storici

I Laboratori **7, 15 e 19** (capitoli 13, 24 e 29) lavorano su un consenso pubblico
archiviato: `collector/consensus-microdesc-2026-09-23-15`, il consenso microdesc delle
15:00 UTC del 23 settembre 2026.

Il file non è nel repository (`labs/*/data/collector/` è escluso da git). Si scarica una
volta sola, su richiesta esplicita, dalla radice del repository:

```bash
make -C labs/it data
```

Il comando scarica da CollecTor l'archivio dei microdescrittori di settembre 2026,
ne estrae soltanto quel consenso e lo salva qui. Né i test né la compilazione del libro
scaricano dati: senza il file, `make verifica-lab` salta i Laboratori 7, 15 e 19 e lo
segnala.

**Lo script controlla solo l'intestazione del formato, non le firme delle autorità.** Un
file con l'intestazione giusta non è per questo autentico; per verificarne le firme serve
il Laboratorio 6 (`directory.py`) con i certificati delle autorità.

Il consenso di prova di Chutney incluso nei test (`codice/torlab/test/dati/`) non sostituisce
questo documento: le cifre dei capitoli 13, 24 e 29 vengono dal consenso pubblico.
