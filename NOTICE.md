# Notice

**Onion Routing Anatomy — Anatomia di Tor. Il protocollo dell'anonimato, byte per byte**
Copyright © 2026 Alessandro Greco.

## License of this work

All original material in this repository — the book text in every language, figures,
cover artwork, LaTeX sources, laboratory code, scripts, network configurations and
documentation — is released under the **GNU General Public License, version 3 or (at your
option) any later version** (SPDX: `GPL-3.0-or-later`). The full text is in
[`LICENSE`](LICENSE). The license covers this material to the extent that the author holds
the rights to it; the items listed below keep their own terms.

The "source code" of the book, in the sense of the GPL, is the content of `source/`
(LaTeX, TikZ figures, bibliography, cover artwork) together with the `Makefile` that turns it
into the PDF and EPUB files in `book/`.

**Translations.** The English, Spanish, Russian and Simplified Chinese translations were
generated with artificial intelligence tools from the Italian original. To the extent that
rights subsist in them, the author releases them under the same license.

## Third-party material

| Material | Where | Terms |
|---|---|---|
| Text of the GNU GPL v3 | `LICENSE` | © Free Software Foundation; verbatim copying permitted, changes not allowed |
| Chutney patch (one line of `lib/chutney/tor/torrc.py`) | `labs/it/laboratorio/chutney-dirport-loopback.patch` | Modification of Chutney, © Nick Mathewson, Michael Stone, The Tor Project; BSD 3-Clause License |
| Patch for tor (exit end reason) | `docs/it/segnalazioni/0001-exit-connectrefused.patch` | Modification of tor, © The Tor Project; offered under tor's BSD 3-Clause License for upstream submission |
| Test vectors from Tor proposals 216 and 332 | the `torlab/test/` folders under `labs/<language>/` | Reference data from the Tor specifications (torspec), used for interoperability tests |
| Public Tor network documents (onion-service descriptor, consensus excerpts) | `torlab/test/dati` and `torlab/test/data` under `labs/<language>/`, listings in the book | Public data of the Tor network retrieved as an ordinary client or from Tor Metrics/CollecTor; not claimed under the GPL |
| Fonts embedded in the PDFs: TeX Gyre Pagella and Heros; DejaVu Sans Mono; Computer Modern (mathematics) | `book/*.pdf` only (not in the repository) | GUST Font License; Bitstream Vera/DejaVu license; SIL Open Font License (AMS Type 1 version). All permit embedding |
| Quotations and bibliographic references | book text, `source/shared/bibliography/tor.bib` | Short, attributed quotations for teaching and discussion (art. 70, Italian law 633/1941); works remain under their authors' terms |

Software that the build or the laboratories **download** — tor, Chutney, obfs4proxy, Arti,
Stem, Debian packages, TeX Live, Python packages such as `cryptography` and `pytest` — is not
included in this repository and keeps its own license.

## Trademarks

“Tor” and the Tor onion logo are trademarks of The Tor Project, Inc. This book is an
independent work: it is **not endorsed or sponsored by, or affiliated with, the Tor
Project**, and it does not use the Tor logo. The onion cross-section on the cover is
original artwork. Other product and service names belong to their respective owners and are
used only to describe them.
