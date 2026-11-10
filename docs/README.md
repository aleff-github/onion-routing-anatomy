# Documentation

## For readers and contributors

| Document | Contents |
|---|---|
| [`editorial-process.md`](editorial-process.md) | States of reports, what a correction needs, editions, versions and releases (English and Italian) |
| [`translation-review.md`](translation-review.md) | How to review a translation, with or without Git (English and Italian) |
| [`translations/`](translations/) | Status of the English, Spanish, Russian and Simplified Chinese editions |
| [`translations/typeset-review-2026-10.md`](translations/typeset-review-2026-10.md) | Review of the typeset pages of the translations (October 2026): checks, defects fixed, limits |
| [`releases/`](releases/) | Release notes |
| [`it/redazione/`](it/redazione/) | Style guide, terminology, originality rules and sources, for contributors (Italian) |
| [`it/procedura-laboratori-dal-vivo.md`](it/procedura-laboratori-dal-vivo.md) | How to rerun the Italian laboratories live (`make verifica-lab`, `make verifica-lab-bridge`), safety checks, backup and recovery of the private network (Italian) |
| [`it/validazione/`](it/validazione/) | Summaries of the live validation of 28 October 2026: 53/53 and 14/14 (Italian) |
| [`it/segnalazioni/`](it/segnalazioni/) | Analysis and patch of the tor exit behaviour discussed in chapter 22 (Italian) |

## For maintainers

| Document | Contents |
|---|---|
| [`maintainers/release-procedure.md`](maintainers/release-procedure.md) | How a release is prepared, checked and published, with the attestations to confirm first |
| [`maintainers/github-pages.md`](maintainers/github-pages.md) | How the website is generated, checked and published on GitHub Pages |
| [`maintainers/github-repository.md`](maintainers/github-repository.md) | Repository description, topics and social preview |

## Reproducibility

- **Book:** `make book` builds every format from `source/` with TeX Live in Docker
  (`texlive/texlive`, TeX Live 2026 at the time of release 1.0.0). PDFs embed the build date,
  so their checksums change from build to build; the text does not.
- **Laboratories:** `labs/it/laboratorio/Dockerfile` pins tor 0.4.9.13 (commit `3c575400`), Chutney
  `6cc1588` with one documented patch, and installs obfs4proxy and the capture tools from
  Debian trixie. `make -C labs/it test` runs the offline tests; `make verifica-lab` and
  `make verifica-lab-bridge` the live checks.
- **Checks on the sources:** `make check` (residual wording, cross-references, listings
  regenerated without network) and `make test` (offline tests of the scripts).
  `make fonti` and `make originalita` need the upstream sources in `fonti/`, which are not
  part of the repository.
