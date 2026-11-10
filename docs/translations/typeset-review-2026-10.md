# Typeset pages of the translations — review of October 2026

Review of the PDF and EPUB files of the English, Spanish, Russian and Simplified Chinese
editions, carried out on 29 and 30 October 2026 in sessions with AI tools. It concerns the
**typeset output**: layout, completeness, code, formulas, references and the words that the
LaTeX setup adds to the text. It is not a linguistic review, it does not replace a reading by
native speakers, and it does not check the technical content against the specifications.

## What was checked

| Check | How | Scope |
|---|---|---|
| Build | `make -C source/<language> pdf epub`; LaTeX log | No errors, no unresolved references, no missing characters, overfull boxes counted and examined one by one |
| Code on the page | `make composizione LINGUE=<language>` (`scripts/check_pdf_code.py`) | Every listing line and every inline code fragment of the sources is found, character for character, in the text of the PDF |
| Every page | Script on the PDF (text and drawings inside the type area, `??`, printed LaTeX commands, replacement characters, space between running head and page number) | All pages of the four PDFs |
| Layout | Thumbnail sheets of all pages, looked at one by one | Overflowing figures and tables, blank or misplaced pages, headings, figure and table placement. At that size the text cannot be read |
| EPUB | `make epub-check LINGUE=<language>` (`scripts/check_epub.py`) and EPUBCheck | Metadata, navigation, every sentence of the sources and every listing line present, formulas with alternative text, figures, tables, quotation marks; 0 errors and 0 warnings in EPUBCheck |
| Formulas | Comparison of every formula of each translation with the Italian original | Differences explained (see below) |
| Words added by macros | Search in the sources for words repeated by `\proposta`, `\cref` and `\termine`, and for consecutive repeated words | All four translations |

The automated checks were tested with deliberately damaged copies (paragraph, sentence or
quotation marks removed, raw alternative text, build date added to the metadata, listing
characters replaced): each damage was reported.

## Defects found and fixed

| Edition | Defect | Fix |
|---|---|---|
| ru, zh-Hans | Listings with Cyrillic or Chinese characters: characters out of place and spaces lost, in the PDF and in the EPUB (11 and 6 lines) | `source/shared/lst-unicode.lua` |
| ru | In listings `-` and `*` printed as mathematical `−` and `∗` (142 code lines and fragments): copied code would not run | `\lst@ttfamily` in the Russian preamble |
| ru | Monospaced paths hyphenated (`ла-боратория`, `shared-rand-current-`) | Monospaced Cyrillic font without hyphenation |
| ru | Version table running off the page and cut (`…переменной длин`); two figures and two tables wider than the text | Column widths, figure spacing |
| ru | `в глава 7`, `из раздел 8`: chapter and section names not declined | Abbreviations `гл.`, `разд.`, `прил.`; full form at the start of a sentence |
| ru | `из Предложение 289`, `в Предложение 359`, `по векторам Предложение 332` (12 places): nominative where another case is needed | Declined form as optional argument of `\proposta` |
| en, es, ru | `Proposal Proposal 355`, `la propuesta Propuesta 340`, `Предложение Предложение 348`, and an English `proposal` in the Russian text (18 places in chapter 31) | Repeated word removed |
| en, es, ru | `chapter 27 examines…`, `глава 26 завершалась…` at the start of a sentence (22, 5 and 11 places) | `\Cref` |
| en | `initiator (initiator)` | Gloss removed |
| zh-Hans | Headings in English (`Chapter`, `Contents`, `Figure`, running heads `CHAPTER 1.`) | ctex headings with Chinese names |
| zh-Hans | References written `章 9 and 13` | `第 9 章和第 13 章`, Chinese conjunctions |
| zh-Hans | Bibliography with English labels (`In:`, `visited on 09/23/2026`, `pp.`) | Chinese labels, ISO dates |
| en, es, ru, zh-Hans | Notes of the shared bibliography in Italian (`Consultato il 23 settembre 2026`, `Bozza`, `Versione 0.34`, …) | Replaced in each translation; the Italian edition is unchanged |
| en, es, ru, zh-Hans | A listing right after an inline heading started on the heading's line, with its frame running off the page (7 places in each edition) | The fix already used in the Italian edition |
| en, es, ru, zh-Hans | 34 overfull boxes (paths, addresses and hexadecimal strings that could not break, wide figures and tables, running heads touching the page number), and four more running heads touching the page number without an overfull warning | Break points in code, column widths, shorter running heads, `\sloppypar` in two paragraphs, a looser tolerance in Chinese; now 0 in all four PDFs |
| en, es | `t_\mathit{key}` without braces stopped the EPUB conversion in chapter 9 | Braces as in the original |

## Formulas compared with the original

All differences between the formulas of a translation and those of the Italian original were
examined. They are of four kinds, none of which changes the content:

- names of variables translated as in the text (`\mathit{periodo}` → `\mathit{period}`,
  `\mathit{sforzo}` → `\mathit{effort}`, `indirizzo` → `address`) and text inside the TikZ
  figures;
- a symbol written in words, or left implicit, instead of repeated as a formula (Spanish:
  "un esfuerzo de 5000" for `E = 5000`; Spanish and Russian: no second `R_1` in the same
  sentence of chapter 9; Chinese: `Y` implicit in `EXP(Y, x)`);
- a condition stated explicitly in the translation and implicit in the original (`y \neq 1`
  in the solution of exercise B.2) or the reverse (`{>}50\%`);
- in Chinese, a few symbols set as formulas where the original writes them in the text
  (`CM`, `SM`, `B_x`, `d = 0`, `1/65536`), with the same values.

## Open issue

- In the index of every edition, the Italian one included, the entry for proposals lists
  `NNN`: appendix C writes the generic form of a proposal name ("Proposal NNN") with
  `\proposta{NNN}`, which also adds an index entry. It changes no content; the fix
  (writing that example without `\proposta`) also changes the Italian edition, so it is left
  to a later version together with a rebuild of `book/it/`.

## What was not checked

- The text has not been reread on the typeset pages; at thumbnail size only the layout is
  visible.
- No native speaker has reviewed any of the translations, and no independent review of
  the translations has taken place.
- The EPUB files were checked with EPUBCheck and by the scripts above, not in reading
  applications.
- The laboratories have not been run in the translated versions.

The state of each edition is in [`en.md`](en.md), [`es.md`](es.md), [`ru.md`](ru.md) and
[`zh-Hans.md`](zh-Hans.md).
