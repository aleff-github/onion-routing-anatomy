# Validazione dei laboratori italiani

Riepiloghi delle prove dal vivo eseguite il 28 ottobre 2026 sulla rete Tor privata di
`labs/it/laboratorio` (tor 0.4.9.13, Chutney `6cc1588` con la patch del DirPort, obfs4proxy 0.0.14),
con i verificatori di questa repository (`make verifica-lab`, `make verifica-lab-bridge`).

| Riepilogo | Esito |
|---|---|
| [`2026-10-28-fase1.md`](2026-10-28-fase1.md) | prima esecuzione completa: 52/53, Lab 18 bloccato dal DNS dell'ambiente |
| [`2026-10-28-fase1-chiusura.md`](2026-10-28-fase1-chiusura.md) | resolver locale per gli exit e DirPort su 127.0.0.1: **53/53** |
| [`2026-10-28-fase2.md`](2026-10-28-fase2.md) | Laboratorio 10, bridge obfs4: **14/14** in tre esecuzioni, rete originale ripristinata con identità integre |

Come ripetere le prove: [`docs/it/procedura-laboratori-dal-vivo.md`](../procedura-laboratori-dal-vivo.md).
I log grezzi non sono pubblicati perché contengono percorsi dell'ambiente in cui le prove sono
state eseguite; anche catture di traffico e chiavi dei nodi non sono pubblicate.
