# Contributing · Contribuire

[English](#english) · [Italiano](#italiano)

---

## English

This book is not a finished product: it can keep improving with the help of the people who
read it. Issues and pull requests can be written in English or Italian (and, for a
translation, in that language).

### The quickest ways to help

| You want to… | Do this | You need |
|---|---|---|
| Report a typo or an unclear sentence | [Typo form](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=01-typo.yml) | A GitHub account |
| Report a translation problem | [Translation form](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=02-translation.yml) | A GitHub account |
| Correct a technical statement | [Technical correction form](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=03-technical-correction.yml) | A primary source |
| Report a laboratory problem | [Laboratory form](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=04-laboratory.yml) | The output of the failing step |
| Improve the documentation | [Documentation form](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=05-documentation.yml) | — |
| Propose new content | [Proposal form](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=06-proposal.yml) | — |
| Review a translation | [Translation review guide](docs/translation-review.md) | Good knowledge of the language |
| Fix something yourself | A pull request (below) | Git, or just the GitHub web editor for small fixes |

A report is a complete contribution: you do not have to change the sources yourself.

### Fixing a small typo without Git

1. Find the file. The Italian text is in `source/it/capitoli/` (one file per chapter, e.g.
   `08-celle.tex`) and `source/it/appendici/`; translations are in `source/<language>/`; the
   laboratory guides are in `labs/<language>/wiki/`.
2. Open it on GitHub and click the pencil icon (*Edit this file*).
3. Change only the text. In `.tex` files leave commands such as `\emph{…}` or `\cite{…}` as
   they are.
4. Click *Commit changes…* → *Propose changes*. GitHub makes a copy of the repository
   (a *fork*) and opens a pull request for you.

You do not need to build the book. The change is checked during the review.

### Larger changes with Git

1. **Open an issue first** for anything beyond a small fix, so that the change can be
   discussed before you spend time on it.
2. **Find the files** (see *Where things are* below).
3. **Fork** the repository, create a branch, make the change.
4. **Verify** it with the checks that fit (table below).
5. **Open a pull request** and fill in the template. Mention the issue (`Fixes #…`).
6. **Answer the review.** Changes may be requested; that is normal.
7. Once merged, the correction goes into the **next version** of the book and is listed in
   the [changelog](CHANGELOG.md).

### Where things are

| Path | Content |
|---|---|
| `source/it/` | Italian original (LaTeX): `capitoli/`, `appendici/`, `figure/` (TikZ); shared bibliography in `source/shared/bibliography/tor.bib` |
| `source/<language>/` | Translations under review, each with its terminology file; their state is in `docs/translations/` |
| `labs/<language>/code/torlab/` | Laboratory code; `labs/<language>/wiki/` guides; `labs/it/laboratorio/` Docker image and private network |
| `scripts/` | Checks, laboratory verification, website generator; tests in `scripts/tests/` |
| `website/` | Website texts in five languages (`website/i18n/`) |
| `docs/` | Process, validation reports, style guide and terminology (`docs/it/redazione/`) |

### Checks

| Change | Run |
|---|---|
| Typo or wording | Nothing required |
| LaTeX sources (`source/`) | `make check`; `make book-pdf` if you can (needs Docker) |
| Translation sources (`source/<language>/`) | `make -C source/<language> check`; with the PDF and EPUB built, `make composizione epub-check LINGUE=<language>` |
| Laboratory code | `make test`; on the private network `make verifica-lab` |
| Scripts | `make test` |
| Website | `make site-check` |

`make check` and `make test` need only Python 3.11 or later and
`pip install -r requirements.txt`. Building the book needs Docker; running the laboratories
needs Docker and the private network (`make -C labs/it immagine avvia`).

### Rules

1. **Safety.** Experiments run only on the private network in `labs/` or as an ordinary Tor
   client — never against public relays or real users (principles of the Tor Research Safety
   Board). Never commit anything from `labs/*/lab/net/` (node keys and identities), traffic
   captures, tokens or personal data.
2. **Primary sources.** Changes to the description of the protocol, the cryptography or the
   laboratories must cite a primary source: Tor specifications, tor or Arti code (with version
   or commit), a proposal (with its number), the original paper — or a reproducible run on the
   private network. Do not invent formats, fields, constants or dates. Distinguish current,
   deprecated and proposed behaviour.
3. **Translations.** A change to a translation must not silently change the Italian original.
   If the original is wrong too, report or fix it there in the same pull request and say so.
4. **Originality.** Write in your own words: no passages translated from specifications,
   papers or other books; short quotations only, marked and attributed. Figures are drawn
   from scratch. See `docs/it/redazione/originalita.md`.
5. **Style and terminology** of the Italian text: `docs/it/redazione/stile.md` and
   `docs/it/redazione/terminologia.md`; for translations, the terminology file in `source/<language>/` (`terminology.md`, `terminologia.md`, `терминология.md`, `术语.md`).
6. **AI tools.** You may use them, but check the result yourself and mention it in the pull
   request. The project documents its own use of AI in [AI_DISCLOSURE.md](AI_DISCLOSURE.md).

How reports are handled and when a correction is accepted: [docs/editorial-process.md](docs/editorial-process.md).

### License of contributions

By opening a pull request you confirm that you have the right to submit the contribution and
that it is released under the project's license, **GPL-3.0-or-later**. There is nothing to
sign. New source files start with the line `SPDX-License-Identifier: GPL-3.0-or-later`, in
the comment syntax of the file.

### Credit

Accepted contributions are listed in [CONTRIBUTORS.md](CONTRIBUTORS.md) and in the changelog,
under your GitHub name or a name you choose. You can ask not to be listed. See also the
[code of conduct](CODE_OF_CONDUCT.md).

### Independence

This project is not affiliated with the Tor Project. Bugs in tor, Arti or the specifications
belong upstream: <https://gitlab.torproject.org/>. Security problems in this repository:
[SECURITY.md](SECURITY.md).

---

## Italiano

Questo libro non è un prodotto finito: può continuare a migliorare grazie a chi lo legge. Issue
e pull request si possono scrivere in italiano o in inglese (e, per una traduzione, nella
lingua di quella traduzione).

### I modi più rapidi per aiutare

| Vuoi… | Fai così | Ti serve |
|---|---|---|
| Segnalare un refuso o una frase poco chiara | [Modulo refusi](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=01-typo.yml) | Un account GitHub |
| Segnalare un errore di traduzione | [Modulo traduzioni](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=02-translation.yml) | Un account GitHub |
| Correggere un'affermazione tecnica | [Modulo correzione tecnica](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=03-technical-correction.yml) | Una fonte primaria |
| Segnalare un problema di laboratorio | [Modulo laboratori](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=04-laboratory.yml) | L'output del passo che non funziona |
| Migliorare la documentazione | [Modulo documentazione](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=05-documentation.yml) | — |
| Proporre nuovi contenuti | [Modulo proposte](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=06-proposal.yml) | — |
| Rivedere una traduzione | [Guida alla revisione](docs/translation-review.md) | Buona conoscenza della lingua |
| Correggere tu stesso | Una pull request (sotto) | Git, oppure solo l'editor web di GitHub per le piccole correzioni |

Una segnalazione è già un contributo completo: non devi modificare tu i sorgenti.

### Correggere un piccolo refuso senza Git

1. Trova il file. Il testo italiano è in `source/it/capitoli/` (un file per capitolo, per
   esempio `08-celle.tex`) e `source/it/appendici/`; le traduzioni in `source/<lingua>/`; le
   guide dei laboratori in `labs/<lingua>/wiki/`.
2. Aprilo su GitHub e fai clic sull'icona della matita (*Edit this file*).
3. Cambia solo il testo. Nei file `.tex` lascia com'erano i comandi come `\emph{…}` o
   `\cite{…}`.
4. Fai clic su *Commit changes…* → *Propose changes*. GitHub crea una copia della repository
   (un *fork*) e apre per te una pull request.

Non serve compilare il libro: la modifica viene controllata durante la revisione.

### Modifiche più ampie con Git

1. **Apri prima una issue** per tutto ciò che va oltre una piccola correzione, così la
   modifica si può discutere prima che tu ci dedichi tempo.
2. **Trova i file** (vedi *Dove si trovano le cose*).
3. **Fai un fork** della repository, crea un branch, applica la modifica.
4. **Verificala** con i controlli adatti (tabella sotto).
5. **Apri una pull request** e compila il modello. Cita la issue (`Fixes #…`).
6. **Rispondi alla revisione.** Possono essere chieste modifiche: è normale.
7. Dopo l'unione, la correzione entra nella **versione successiva** del libro ed è elencata
   nel [changelog](CHANGELOG.md).

### Dove si trovano le cose

| Percorso | Contenuto |
|---|---|
| `source/it/` | Originale italiano (LaTeX): `capitoli/`, `appendici/`, `figure/` (TikZ); bibliografia comune in `source/shared/bibliography/tor.bib` |
| `source/<lingua>/` | Traduzioni in revisione, ciascuna con il proprio file di terminologia; il loro stato è in `docs/translations/` |
| `labs/<lingua>/code/torlab/` | Codice dei laboratori; guide in `labs/<lingua>/wiki/`; immagine Docker e rete privata in `labs/it/laboratorio/` |
| `scripts/` | Controlli, verifica dei laboratori, generatore del sito; test in `scripts/tests/` |
| `website/` | Testi del sito in cinque lingue (`website/i18n/`) |
| `docs/` | Processo, rapporti di validazione, guida di stile e terminologia (`docs/it/redazione/`) |

### Controlli

| Modifica | Esegui |
|---|---|
| Refuso o formulazione | Niente di obbligatorio |
| Sorgenti LaTeX (`source/`) | `make check`; `make book-pdf` se puoi (serve Docker) |
| Sorgenti delle traduzioni (`source/<lingua>/`) | `make -C source/<lingua> check`; con PDF ed EPUB compilati, `make composizione epub-check LINGUE=<lingua>` |
| Codice dei laboratori | `make test`; sulla rete privata `make verifica-lab` |
| Script | `make test` |
| Sito | `make site-check` |

`make check` e `make test` richiedono solo Python 3.11 o successivo e
`pip install -r requirements.txt`. Per compilare il libro serve Docker; per i laboratori,
Docker e la rete privata (`make -C labs/it immagine avvia`).

### Regole

1. **Sicurezza.** Gli esperimenti si fanno solo sulla rete privata di `labs/` o come normale
   client Tor, mai contro relay pubblici o utenti reali (principi del Tor Research Safety
   Board). Non registrare mai nulla di `labs/*/lab/net/` (chiavi e identità dei nodi),
   catture di traffico, token o dati personali.
2. **Fonti primarie.** Le modifiche alla descrizione del protocollo, alla crittografia o ai
   laboratori devono citare una fonte primaria: specifiche di Tor, codice di tor o Arti (con
   versione o commit), una proposta (con il numero), l'articolo originale, oppure una prova
   riproducibile sulla rete privata. Non inventare formati, campi, costanti o date.
   Distingui il comportamento attuale, deprecato e proposto.
3. **Traduzioni.** Una correzione a una traduzione non deve modificare in silenzio
   l'originale italiano. Se anche l'originale è sbagliato, segnalalo o correggilo nella
   stessa pull request e dillo esplicitamente.
4. **Originalità.** Scrivi con parole tue: niente passaggi tradotti da specifiche, articoli o
   altri libri; solo brevi citazioni, segnalate e attribuite. Le figure si disegnano da zero.
   Vedi `docs/it/redazione/originalita.md`.
5. **Stile e terminologia** del testo italiano: `docs/it/redazione/stile.md` e
   `docs/it/redazione/terminologia.md`; per le traduzioni, il file di terminologia in `source/<lingua>/` (`terminology.md`, `terminologia.md`, `терминология.md`, `术语.md`).
6. **Strumenti di AI.** Puoi usarli, ma controlla tu il risultato e indicalo nella pull
   request. Il progetto documenta il proprio uso dell'AI in [AI_DISCLOSURE.md](AI_DISCLOSURE.md).

Come vengono gestite le segnalazioni e quando una correzione viene accettata:
[docs/editorial-process.md](docs/editorial-process.md).

### Licenza dei contributi

Aprendo una pull request confermi di avere il diritto di inviare il contributo e che esso è
distribuito con la licenza del progetto, **GPL-3.0-or-later**. Non c'è niente da firmare. I
nuovi file sorgente iniziano con la riga `SPDX-License-Identifier: GPL-3.0-or-later`, nella
sintassi di commento del file.

### Riconoscimenti

I contributi accettati sono elencati in [CONTRIBUTORS.md](CONTRIBUTORS.md) e nel changelog,
con il tuo nome GitHub o un nome a tua scelta. Puoi chiedere di non comparire. Vedi anche il
[codice di condotta](CODE_OF_CONDUCT.md).

### Indipendenza

Questo progetto non è affiliato al Tor Project. I bug di tor, Arti o delle specifiche vanno
segnalati a monte: <https://gitlab.torproject.org/>. Problemi di sicurezza in questa
repository: [SECURITY.md](SECURITY.md).
