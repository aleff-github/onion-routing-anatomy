# Editorial process · Processo editoriale

[English](#english) · [Italiano](#italiano)

## English

How reports and pull requests become corrections in a new version of the book. The process
is deliberately light: it exists to keep the book correct and every change traceable.

### States of a report

Every issue gets a type label from its form (`typo`, `translation`, `technical`,
`laboratory`, `documentation`, `proposal`) and starts as `status: to verify`. A language
label (`lang: it`, `lang: en`, `lang: es`, `lang: ru`, `lang: zh-Hans`) is added when useful.

| Label | Italiano | Meaning |
|---|---|---|
| `status: to verify` | Da verificare | Received, not checked yet |
| `status: confirmed` | Confermata | The problem is real and will be fixed |
| `status: in progress` | In lavorazione | Someone is working on it (say so in a comment to avoid duplicate work) |
| `status: fix proposed` | Correzione proposta | A pull request is open |
| `status: resolved` | Risolta | Fixed on `main`; it will be in the next version. The issue is closed |
| `status: not reproducible` | Non riproducibile | Could not be reproduced with the information given; it can be reopened with more details |
| `status: duplicate` | Duplicata | Already reported; the comment links the original issue |

A report that turns out not to be an error is closed with an explanation. Nobody is
expected to answer within a fixed time.

### What a correction needs

| Kind of change | Required before merging |
|---|---|
| Typo, punctuation, wording | A quick read by the maintainer |
| Translation | The Italian original as reference; for terminology, the terminology file in `source/<language>/`. Preferably a second speaker of the language |
| Protocol, cryptography, formats, constants | A primary source: Tor specifications, tor or Arti code at a stated version or commit, proposal number, original paper. Current, deprecated and proposed behaviour kept distinct |
| Laboratories and their code | `make test`, and a run on the private network (`make verifica-lab` or the relevant laboratory) with its output |
| Legal and ethical content (chapter 25) | A source (law, ruling, official guidance) and particular care; such changes are flagged in the changelog |
| Website | `make site-check` |

Every pull request is reviewed before it is merged; nothing is pushed directly to `main` by
contributors.

**Translations never change the Italian original silently.** If a translation problem comes
from the original, the original is fixed first (or in the same pull request, stated
explicitly) and the other translations are checked for the same problem.

### Versions and releases

Every language edition belongs to the same edition of the work: the current one is the
**first edition**, version `1.0.0`, in all five languages. Versions follow
`MAJOR.MINOR.PATCH`; the edition (first, second, …) is the same in every language and changes
only with a MAJOR version. Corrections within an edition can be released one language at a
time, with the tag `vX.Y.Z-<language>` (for example `v1.0.0-it`).

- **PATCH** (1.0.1): editorial and technical corrections that do not change the structure.
- **MINOR** (1.1.0): new or rewritten sections, figures, exercises or laboratories; a new
  reference version of tor or Arti (after rerunning the laboratories with
  `make verifica-lab`).
- **MAJOR** (2.0.0): reorganisation of the book.

Before a release: the [changelog](../CHANGELOG.md) has the new section; `VERSIONE` in the
`Makefile` and `edition.version` in `website/site.toml` match; `make check`, `make test` and
`make site-check` pass; the files are rebuilt (`make book`) and packaged
(`make release-package`, which writes `SHA256SUMS`); the notes are in
`docs/releases/vX.Y.Z-<language>.md`. The tag and the GitHub release are created only with
the maintainer's approval. The tag points at the commit the files were built from, so every
published file can be traced to its sources.

A **translation** is released (files and download link) only when its review is complete
(including native or fluent speakers), its PDF and EPUB have been built and checked, and the
maintainer has approved it. Until then its sources are in the repository, with no release and
no download link.

### Changelog

[CHANGELOG.md](../CHANGELOG.md) groups the changes of each version under: *Editorial
corrections*, *Technical corrections*, *Laboratories*, *Translations*, *Website and
documentation*. Each entry links the issue or pull request and credits its author (see
[CONTRIBUTORS.md](../CONTRIBUTORS.md)).

---

## Italiano

Come segnalazioni e pull request diventano correzioni in una nuova versione del libro. Il
processo è volutamente leggero: serve a mantenere il libro corretto e ogni modifica
rintracciabile.

### Stati di una segnalazione

Ogni issue riceve dal suo modulo un'etichetta di tipo (`typo`, `translation`, `technical`,
`laboratory`, `documentation`, `proposal`) e parte come `status: to verify`. Quando serve si
aggiunge un'etichetta di lingua (`lang: it`, `lang: en`, `lang: es`, `lang: ru`,
`lang: zh-Hans`).

| Etichetta | Stato | Significato |
|---|---|---|
| `status: to verify` | Da verificare | Ricevuta, non ancora controllata |
| `status: confirmed` | Confermata | Il problema è reale e sarà corretto |
| `status: in progress` | In lavorazione | Qualcuno ci sta lavorando (scrivilo in un commento, per evitare lavoro doppio) |
| `status: fix proposed` | Correzione proposta | C'è una pull request aperta |
| `status: resolved` | Risolta | Corretta su `main`; sarà nella prossima versione. La issue viene chiusa |
| `status: not reproducible` | Non riproducibile | Non riprodotta con le informazioni date; si può riaprire con più dettagli |
| `status: duplicate` | Duplicata | Già segnalata; il commento rimanda alla issue originale |

Una segnalazione che si rivela non essere un errore viene chiusa con una spiegazione. Non ci
sono tempi di risposta garantiti.

### Che cosa serve a una correzione

| Tipo di modifica | Necessario prima dell'unione |
|---|---|
| Refuso, punteggiatura, formulazione | Una lettura rapida di chi mantiene il progetto |
| Traduzione | L'originale italiano come riferimento; per la terminologia, il file di terminologia in `source/<lingua>/`. Meglio se c'è un secondo parlante della lingua |
| Protocollo, crittografia, formati, costanti | Una fonte primaria: specifiche di Tor, codice di tor o Arti a una versione o commit indicati, numero della proposta, articolo originale. Comportamento attuale, deprecato e proposto tenuti distinti |
| Laboratori e loro codice | `make test` e un'esecuzione sulla rete privata (`make verifica-lab` o il laboratorio interessato) con il relativo output |
| Contenuti legali ed etici (capitolo 25) | Una fonte (norma, sentenza, indicazione ufficiale) e particolare cautela; queste modifiche sono evidenziate nel changelog |
| Sito | `make site-check` |

Ogni pull request viene rivista prima dell'unione; chi contribuisce non invia modifiche
direttamente su `main`.

**Le traduzioni non modificano mai in silenzio l'originale italiano.** Se un problema di
traduzione nasce dall'originale, si corregge prima l'originale (o nella stessa pull request,
dichiarandolo) e si controlla se le altre traduzioni hanno lo stesso problema.

### Versioni e release

Tutte le edizioni linguistiche appartengono alla stessa edizione dell'opera: quella attuale è
la **prima edizione**, versione `1.0.0`, in tutte e cinque le lingue. Le versioni seguono
`MAJOR.MINOR.PATCH`; l'edizione (prima, seconda, …) è la stessa in ogni lingua e cambia solo con
una versione MAJOR. Le correzioni di un'edizione possono uscire una lingua alla volta, con il tag
`vX.Y.Z-<lingua>` (per esempio `v1.0.0-it`).

- **PATCH** (1.0.1): correzioni editoriali e tecniche che non cambiano la struttura.
- **MINOR** (1.1.0): sezioni, figure, esercizi o laboratori nuovi o riscritti; una nuova
  versione di riferimento di tor o Arti (dopo aver rieseguito i laboratori con
  `make verifica-lab`).
- **MAJOR** (2.0.0): riorganizzazione del libro.

Prima di una release: il [changelog](../CHANGELOG.md) ha la nuova sezione; `VERSIONE` nel
`Makefile` ed `edition.version` in `website/site.toml` coincidono; `make check`, `make test` e
`make site-check` passano; i file sono rigenerati (`make book`) e impacchettati
(`make release-package`, che scrive `SHA256SUMS`); le note sono in
`docs/releases/vX.Y.Z-<lingua>.md`. Il tag e la release GitHub si creano solo con
l'approvazione di chi mantiene il progetto. Il tag punta al commit da cui sono stati generati i file, così
ogni file pubblicato si ricollega ai suoi sorgenti.

Una **traduzione** viene rilasciata (file e link di download) solo quando la revisione è
completa (compresa quella di madrelingua o parlanti esperti), PDF ed EPUB sono stati generati e
controllati e chi mantiene il progetto l'ha approvata. Fino ad allora i sorgenti sono nella
repository, senza release né link di download.

### Changelog

[CHANGELOG.md](../CHANGELOG.md) raggruppa le modifiche di ogni versione in: *Correzioni
editoriali*, *Correzioni tecniche*, *Laboratori*, *Traduzioni*, *Sito e documentazione*. Ogni
voce rimanda alla issue o alla pull request e ne riconosce l'autore (vedi
[CONTRIBUTORS.md](../CONTRIBUTORS.md)).
