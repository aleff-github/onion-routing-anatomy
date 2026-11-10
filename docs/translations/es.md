# Español translation — source translation

This AI-generated source translation accompanies the Italian edition. It is available
for technical and linguistic review, not as an independently validated PDF or EPUB.
The Italian original remains the reference.

| Item | State (October 2026) |
|---|---|
| Origin | Generated with artificial intelligence tools from the Italian original |
| Content | Preface, chapters 1–31, appendices A–D, 39 figures with alternative text, 25 laboratory guides in `labs/es/wiki/` |
| Source review | Sequential line-by-line review of all 191 files of this edition completed on 26 October 2026 (734/734 files across the four translations). Still open: reconciliation of files changed after their review and a few documented findings |
| Static checks | Passed (structure, figures, alternative text); `make check` here checks only structure |
| Offline tests of `labs/es/codigo` | 91 passed in `codigo`, plus 184 passed and 5 expected failures in the `laboratorio` scripts (`make -C labs/es test`; Linux, Python 3.11, 30 October 2026) |
| PDF / EPUB build | PDF: builds without errors (302 pages, no unresolved references, 0 overfull boxes). EPUB: builds without errors; EPUBCheck 0 errors, 0 warnings; `make epub-check LINGUE=es` passes (metadata, every sentence of the sources and every listing present, formulas with alternative text, figures, tables, quotation marks). Built on 30 October 2026 with TeX Live in Docker |
| Typeset pages | All 302 PDF pages checked on 30 October 2026: automatically (text and drawings inside the type area, no `??`, no printed LaTeX commands or replacement characters, running heads clear of the page number, every listing line and code fragment found in the PDF text: `make composizione LINGUE=es`) and visually as thumbnail sheets, for layout only (overflowing figures and tables, blank or misplaced pages). The text has not been reread on the typeset pages, and no native speaker has reviewed it. Details: [`typeset-review-2026-10.md`](typeset-review-2026-10.md) |
| Live laboratories on the private network | Not run |

Build (requires LuaLaTeX, latexmk, biber and tex4ebook, for example the `texlive/texlive` Docker image used by the root `Makefile`):

```bash
make -C source/es check    # structural checks only
make -C source/es pdf      # main.pdf (draft)
make -C source/es epub     # epub.epub (draft)
```

`macros.tex` loads the Italian macros (`source/it/macro.tex`); the bibliography is shared by all
editions (`source/shared/bibliography/tor.bib`). Help with the review is welcome: see `CONTRIBUTING.md`.

License: GPL-3.0-or-later, like the rest of the work (see `NOTICE.md` on translations).
