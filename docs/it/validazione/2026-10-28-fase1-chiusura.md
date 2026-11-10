# Evidenze — chiusura della FASE 1 (28/10/2026, pomeriggio): LV-13 e DirPort

I file elencati sotto, i log grezzi e la relazione completa non sono pubblicati perché contengono
percorsi dell'ambiente di prova. Nessun file contiene chiavi
private; le copie della rete restano fuori dal repository.

| File | Contenuto |
|---|---|
| `backup-net.txt` | copia prima delle modifiche: percorso, dimensione, impronte RSA/Ed25519, certificati |
| `build-immagine.log` | ricostruzione dell'immagine con la patch di Chutney (tor in cache) |
| `torrc-prima-migrazione.sha256`, `migrazione.log`, `torrc-dopo-migrazione.sha256` | migrazione dei `torrc` esistenti (8 relay) |
| `riavvia.log`, `riavvio.tempi` | ripresa della rete senza `chutney init` |
| `chutney-verify.log`, `chutney-verify-3.log` | 2/2 falliti a 1 minuto (onion service), 4/0 a 8 minuti |
| `ascolti.txt`, `rete-loopback-controlla.log` | ascolti reali: tutti su 127.0.0.1 |
| `prova-senza-resolver.txt` | exit senza resolver locale: nessun ripiego esterno |
| `lab18-ripetuto*.log`, `fuga_dns-diretto-2.*` | Lab 18 da solo: 2/3 (prima della correzione SIGHUP), poi 3/3 |
| `verifica-lab-4/5/6.*` | `make verifica-lab`: 51/52 (Lab 20, `arti_config.py`), 53/53, 53/53 con resolver interrogato |
| `test-torlab.log`, `test-strumenti.log` | 93/93 e 122/122 |
| `chiusura.txt` | stato finale: salute, chiavi, `torrc`, processi, socket |
