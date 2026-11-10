# AI disclosure · Uso dell'intelligenza artificiale

[English](#english) · [Italiano](#italiano)

---

## English

This document explains how artificial intelligence was used to make *Anatomia di Tor*
(*Onion Routing Anatomy*). It describes the human direction, the role of AI tools, the checks performed and their limits.

### Study materials, editorial method and purpose

This work grew from notes and study documents that I produced over several years, beginning
with my bachelor's thesis. They provided the starting point and editorial direction for the
book. AI tools then contributed substantially to expanding, explaining, structuring and
drafting the present text, figures, exercises and code. This is **not** a claim that the
finished text was all personally written and merely polished by AI; nor does it mean that
every passage can be traced to a particular earlier note.

The project is offered **free of charge through its official channels** and released, to
the extent that I hold the necessary rights, under **GPL-3.0-or-later** so that others can
study, verify, share and improve it. The guiding principle is *"diffusione dei saperi senza
fondare poteri"* — sharing knowledge without establishing power. The GPL also permits
commercial redistribution under its terms. Internal review and automated tests cannot
guarantee accuracy: readers are invited to report errors and contribute corrections.

### My part

- **The origin of the project.** The book grows out of my study of Tor, begun for my
  bachelor's thesis and continued after university. The book presents an independent technical treatment of the Tor protocol.
- **Direction and decisions.** I defined the goals, technical scope, editorial structure, title, license and free
  distribution, and directed the verification of the laboratories.
- **Review and responsibility.** I follow the development of the work, review it and correct
  it, and I decide what is published. Editorial responsibility for the book is mine.

### What AI tools did

- **Writing the book.** The chapters, appendices, preface, TikZ figures, exercises and solutions were drafted
  with Claude Code (Anthropic), under my instructions and editorial direction. **Text, figures
  and exercises should be regarded as AI-generated under human direction**, rather than
  solely as my own writing polished with AI.
- **Code and laboratories.** The `torlab` package, the private-network laboratory (Docker,
  Chutney), the verification scripts and the build system were written in the same way.
- **Checking.** Technical statements were checked against primary sources (torspec, the tor
  and Arti source code, proposals, papers) during the same AI sessions, with scripts that
  compare the text with the sources and regenerate the listings. The checks do not constitute an independent expert review.
- **Translations.** The English, Spanish, Russian and Simplified Chinese translations were
  generated with AI tools. Their subsequent checks also used AI tools; no independent review by native speakers
  has been completed.
- **This project's documentation**, including this file, the README, the website and the
  cover, was drafted with AI from information I provided.

### How the work is checked, and the limits

**Internal review.** The work is reviewed and maintained by me, as the person who started the
project, and it keeps being corrected and improved.

**Automated and experimental checks**, run in the AI sessions:

- live execution of the 20 Italian laboratories on a private Tor network (tor 0.4.9.13):
  **53/53** checks, plus **14/14** for the obfs4 bridge laboratory, on 28 October 2026;
- offline tests of the code and of the scripts, regeneration of the listings without network;
- builds of the PDF and EPUB with page-by-page programmatic checks, EPUBCheck validation and
  visual inspection of rendered pages.

**Independent review.** None has taken place so far:

- no peer review or technical validation by external experts;
- no review of chapter 25 (legal aspects) by a lawyer;
- no review of the translations by native speakers.

Errors can therefore remain. If you find one, please report it: see
[CONTRIBUTING.md](CONTRIBUTING.md). Corrections are acknowledged in the changelog and in
[CONTRIBUTORS.md](CONTRIBUTORS.md). This document will be updated if independent reviews take
place.

---

## Italiano

Questo documento spiega come l'intelligenza artificiale è stata usata per realizzare *Anatomia
di Tor* (*Onion Routing Anatomy*). Descrive la direzione umana, il ruolo degli strumenti di AI, le verifiche svolte e i loro limiti.

### Materiali di studio, metodo editoriale e finalità

L'opera nasce da appunti e documenti di studio che ho prodotto nel corso degli anni, a
partire dalla mia tesi di laurea triennale. Questi materiali hanno costituito la base e
l'orientamento editoriale del libro. Gli strumenti di intelligenza artificiale hanno poi
contribuito in modo sostanziale ad approfondire, argomentare, strutturare e redigere il testo,
le figure, gli esercizi e il codice. **Non** intendo sostenere che il testo finale sia stato
interamente scritto da me e soltanto corretto dall'IA, né che ogni passaggio sia riconducibile
a uno specifico appunto precedente.

Il progetto è offerto **gratuitamente tramite i suoi canali ufficiali** e distribuito, nella
misura in cui dispongo dei diritti necessari, sotto **GPL-3.0-or-later**, affinché altri
possano studiarlo, verificarlo, condividerlo e migliorarlo. Il principio che guida questa
scelta è la **«diffusione dei saperi senza fondare poteri»**. La GPL permette anche la
redistribuzione commerciale alle proprie condizioni. La revisione interna e i test automatici
non garantiscono l'assenza di errori: invito a segnalarli e a proporre correzioni.

### La mia parte

- **L'origine del progetto.** Il libro nasce dallo studio di Tor che ho iniziato per la mia
  tesi di laurea triennale e ho proseguito dopo l'università. Il libro propone una trattazione tecnica autonoma del protocollo Tor.
- **Direzione e decisioni.** Ho definito gli obiettivi, l'ambito tecnico, la struttura editoriale, il titolo,
  la licenza e la distribuzione gratuita, e diretto la verifica dei laboratori.
- **Revisione e responsabilità.** Seguo lo sviluppo dell'opera, la rivedo e la correggo, e
  decido che cosa pubblicare. La responsabilità editoriale del libro è mia.

### Che cosa hanno fatto gli strumenti di AI

- **La stesura del libro.** I capitoli, le appendici, la prefazione, le figure TikZ, gli esercizi e le soluzioni
  sono stati redatti con Claude Code (Anthropic), sotto la mia direzione editoriale. **Testo,
  figure ed esercizi vanno considerati generati con l'AI sotto direzione umana**, non
  semplicemente scritti da me e rifiniti con l'AI.
- **Codice e laboratori.** Allo stesso modo sono stati scritti il pacchetto `torlab`, il
  laboratorio con la rete privata (Docker, Chutney), gli script di verifica e il sistema di
  build.
- **Verifiche.** Le affermazioni tecniche sono state controllate sulle fonti primarie
  (torspec, codice di tor e di Arti, proposte, articoli) nelle stesse sessioni con l'AI, con
  script che confrontano il testo con le fonti e rigenerano i listati. Questi controlli non equivalgono a una revisione indipendente da parte di esperti.
- **Traduzioni.** Le traduzioni in inglese, spagnolo, russo e cinese semplificato sono state
  generate con strumenti di AI. Anche i controlli successivi hanno utilizzato strumenti di AI; non è stata completata
  una revisione indipendente da parte di madrelingua.
- **La documentazione del progetto**, compresi questo file, il README, il sito e la copertina,
  è stata redatta con l'AI a partire dalle informazioni che ho fornito.

### Come viene controllato il lavoro, e i limiti

**Revisione interna.** L'opera è rivista e mantenuta da me, che ho avviato il progetto, e
continua a essere corretta e migliorata.

**Controlli automatici e sperimentali**, eseguiti nelle sessioni con l'AI:

- esecuzione dal vivo dei 20 laboratori italiani su una rete Tor privata (tor 0.4.9.13):
  **53/53** controlli, più **14/14** per il laboratorio sul bridge obfs4, il 28 ottobre 2026;
- test offline del codice e degli script, rigenerazione dei listati senza rete;
- compilazione del PDF e dell'EPUB con controlli programmatici pagina per pagina, validazione
  EPUBCheck e ispezione visiva delle pagine.

**Revisione indipendente.** Finora non ce n'è stata nessuna:

- nessuna peer review né validazione tecnica da parte di esperti esterni;
- nessuna revisione del capitolo 25 (aspetti legali) da parte di un giurista;
- nessuna revisione delle traduzioni da parte di madrelingua.

Possono quindi restare errori. Se ne trovi uno, segnalalo: vedi
[CONTRIBUTING.md](CONTRIBUTING.md). Le correzioni sono riconosciute nel changelog e in
[CONTRIBUTORS.md](CONTRIBUTORS.md). Questo documento sarà aggiornato se ci saranno revisioni
indipendenti.
