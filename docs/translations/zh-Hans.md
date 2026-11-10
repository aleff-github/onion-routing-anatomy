# 简体中文 (Simplified Chinese) translation — source translation

This AI-generated source translation accompanies the Italian edition. It is available
for technical and linguistic review, not as an independently validated PDF or EPUB.
The Italian original remains the reference.

| Item | State (October 2026) |
|---|---|
| Origin | Generated with artificial intelligence tools from the Italian original |
| Content | Preface, chapters 1–31, appendices A–D, 39 figures with alternative text, 25 laboratory guides in `labs/zh-Hans/维基/` |
| Source review | Sequential line-by-line review of all 181 files of this edition completed on 26 October 2026 (734/734 files across the four translations). Still open: reconciliation of files changed after their review and a few documented findings |
| Static checks | Passed (structure, figures, alternative text); `make check` here checks only structure |
| Offline tests of `labs/zh-Hans/代码` | 91 passed (`make -C labs/zh-Hans test`; Linux, Python 3.11, 30 October 2026) |
| PDF / EPUB build | PDF: builds without errors (262 pages, no unresolved references, 0 overfull boxes). EPUB: builds without errors; EPUBCheck 0 errors, 0 warnings; `make epub-check LINGUE=zh-Hans` passes (metadata, every sentence of the sources and every listing present, formulas with alternative text, figures, tables, quotation marks). Produced through the DVI mode of tex4ebook with fontspec and the Fandol fonts of TeX Live (ctex, used for the PDF, does not work in that mode); Chinese names of chapters, parts, figures and tables. Built on 30 October 2026 with TeX Live in Docker |
| Typeset pages | All 262 PDF pages checked on 30 October 2026: automatically (text and drawings inside the type area, no `??`, no printed LaTeX commands or replacement characters, running heads clear of the page number, every listing line and code fragment found in the PDF text: `make composizione LINGUE=zh-Hans`) and visually as thumbnail sheets, for layout only (overflowing figures and tables, blank or misplaced pages). The text has not been reread on the typeset pages, and no native speaker has reviewed it. Details: [`typeset-review-2026-10.md`](typeset-review-2026-10.md) |
| Live laboratories on the private network | Not run |

Build (requires LuaLaTeX, latexmk, biber and tex4ebook, for example the `texlive/texlive` Docker image used by the root `Makefile`):

```bash
make -C source/zh-Hans check    # structural checks only
make -C source/zh-Hans pdf      # main.pdf (draft)
make -C source/zh-Hans epub     # epub.epub (draft)
```

`宏.tex` loads the Italian macros (`source/it/macro.tex`); the bibliography is shared by all
editions (`source/shared/bibliography/tor.bib`). Help with the review is welcome: see `CONTRIBUTING.md`.

License: GPL-3.0-or-later, like the rest of the work (see `NOTICE.md` on translations).
