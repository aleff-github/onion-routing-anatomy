# Translation review · Revisione delle traduzioni

[English](#english) · [Italiano](#italiano)

## English

The Italian edition is the reference. Source translations into **English, Spanish, Russian
and Simplified Chinese** were generated and checked with AI tools (see
[AI_DISCLOSURE.md](../AI_DISCLOSURE.md)). They have not been independently reviewed by
native speakers. You can help improve their accuracy and readability, even one chapter at a time.

### What you need

- Good knowledge of the target language, and enough Italian or technical background to
  compare with the original (the Italian PDF, or `source/it/`).
- A GitHub account. Git and LaTeX are optional.

### Where the text is

| What | Italian original | Translation |
|---|---|---|
| Chapters | `source/it/capitoli/` | `source/en/chapters/`, `source/es/capitulos/`, `source/ru/главы/`, `source/zh-Hans/章节/` |
| Appendices | `source/it/appendici/` | `source/en/appendices/`, `source/es/apendices/`, `source/ru/приложения/`, `source/zh-Hans/附录/` |
| Figures (labels inside diagrams) | `source/it/figure/` | `source/en/figures/`, `source/es/figuras/`, `source/ru/рисунки/`, `source/zh-Hans/图/` |
| Laboratory guides | `labs/it/wiki/` | `labs/en/wiki/`, `labs/es/wiki/`, `labs/ru/вики/`, `labs/zh-Hans/维基/` |
| Agreed terminology | `docs/it/redazione/terminologia.md` | `source/en/terminology.md`, `source/es/terminologia.md`, `source/ru/терминология.md`, `source/zh-Hans/术语.md` |
| Known state and open points | — | `docs/translations/<language>.md` |

`<language>` is `en`, `es`, `ru` or `zh-Hans`. Chapter files keep the chapter number
(`09-…`) and have names in the language of the edition. The `.tex` files are readable as plain text:
ignore the commands (`\section{…}`, `\cite{…}`) and read the sentences.

### What to look for

1. **Meaning.** Does the sentence say what the Italian says — no more, no less?
2. **Technical terms.** Are they the ones in `terminologia.md`, used consistently? If a term
   there is wrong for your language, say so: the glossary can change.
3. **Naturalness.** Would a technical reader in your language write it this way?
4. **Untranslated or garbled text**, broken formatting, numbers or identifiers that differ
   from the original (`RELAY_EARLY`, field sizes, version numbers must match exactly).

You do not need to check the technical content against the specifications: if you suspect
the original itself is wrong, report it with the
[technical correction form](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=03-technical-correction.yml).

### How to report

- **A few passages:** use the
  [translation form](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=02-translation.yml),
  one issue per problem or several passages in one issue.
- **A whole chapter with Git:** open a *draft* pull request early, with the language and the
  chapter in the title (for example `[es] Review of chapter 9`), so others know it is taken.
  Edit only the translation; the Italian original changes only in a separate, explicit
  correction.
- **A whole chapter without Git:** edit the file in the GitHub web editor and choose
  *Propose changes* (see [CONTRIBUTING.md](../CONTRIBUTING.md)).

When a chapter has been reviewed, it is recorded in `docs/translations/<language>.md` and the
reviewer is credited in [CONTRIBUTORS.md](../CONTRIBUTORS.md), under the name they choose.

---

## Italiano

L'edizione italiana è il riferimento. Le traduzioni nei sorgenti in **inglese, spagnolo,
russo e cinese semplificato** sono state generate e controllate con strumenti di AI (vedi
[AI_DISCLOSURE.md](../AI_DISCLOSURE.md)), ma non sono state sottoposte a una revisione
indipendente da parte di madrelingua. Puoi contribuire a migliorarne accuratezza e naturalezza,
anche soltanto per un capitolo.

### Che cosa serve

- Una buona conoscenza della lingua d'arrivo, e abbastanza italiano o basi tecniche per
  confrontare con l'originale (il PDF italiano, oppure `source/it/`).
- Un account GitHub. Git e LaTeX sono facoltativi.

### Dove si trova il testo

| Che cosa | Originale italiano | Traduzione |
|---|---|---|
| Capitoli | `source/it/capitoli/` | `source/en/chapters/`, `source/es/capitulos/`, `source/ru/главы/`, `source/zh-Hans/章节/` |
| Appendici | `source/it/appendici/` | `source/en/appendices/`, `source/es/apendices/`, `source/ru/приложения/`, `source/zh-Hans/附录/` |
| Figure (testi nei diagrammi) | `source/it/figure/` | `source/en/figures/`, `source/es/figuras/`, `source/ru/рисунки/`, `source/zh-Hans/图/` |
| Guide dei laboratori | `labs/it/wiki/` | `labs/en/wiki/`, `labs/es/wiki/`, `labs/ru/вики/`, `labs/zh-Hans/维基/` |
| Terminologia concordata | `docs/it/redazione/terminologia.md` | `source/en/terminology.md`, `source/es/terminologia.md`, `source/ru/терминология.md`, `source/zh-Hans/术语.md` |
| Stato e punti aperti | — | `docs/translations/<lingua>.md` |

`<lingua>` è `en`, `es`, `ru` o `zh-Hans`. I file dei capitoli conservano il numero del
capitolo (`09-…`) e hanno il nome nella lingua dell'edizione. I file `.tex` si leggono come testo semplice:
ignora i comandi (`\section{…}`, `\cite{…}`) e leggi le frasi.

### Che cosa controllare

1. **Il significato.** La frase dice ciò che dice l'italiano, né più né meno?
2. **I termini tecnici.** Sono quelli di `terminologia.md`, usati in modo coerente? Se un
   termine del glossario è sbagliato per la tua lingua, dillo: il glossario si può cambiare.
3. **La naturalezza.** Un lettore tecnico della tua lingua scriverebbe così?
4. **Testo non tradotto o corrotto**, impaginazione rovinata, numeri o identificatori diversi
   dall'originale (`RELAY_EARLY`, dimensioni dei campi, numeri di versione devono coincidere).

Non devi verificare il contenuto tecnico sulle specifiche: se sospetti che sia sbagliato
l'originale, segnalalo con il
[modulo di correzione tecnica](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=03-technical-correction.yml).

### Come segnalare

- **Pochi passaggi:** usa il
  [modulo per le traduzioni](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=02-translation.yml),
  una issue per problema oppure più passaggi nella stessa issue.
- **Un capitolo intero con Git:** apri presto una pull request in *bozza* (draft), con lingua
  e capitolo nel titolo (per esempio `[es] Review of chapter 9`), così gli altri sanno che è
  preso. Modifica solo la traduzione; l'originale italiano cambia solo con una correzione
  separata ed esplicita.
- **Un capitolo intero senza Git:** modifica il file con l'editor web di GitHub e scegli
  *Propose changes* (vedi [CONTRIBUTING.md](../CONTRIBUTING.md)).

Quando un capitolo è stato rivisto, lo si registra in `docs/translations/<lingua>.md` e chi l'ha
rivisto è riconosciuto in [CONTRIBUTORS.md](../CONTRIBUTORS.md), con il nome che preferisce.
