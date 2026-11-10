# Releases

| Release | Notes | State |
|---|---|---|
| `v1.0.0-it` | [v1.0.0-it.md](../releases/v1.0.0-it.md) | **In preparation** — files built and packaged, tag and GitHub release not yet created |

## Automated pre-release QA (no publication)

The workflow [`.github/workflows/italian-release-qa.yml`](../../.github/workflows/italian-release-qa.yml)
runs source checks and offline tests, then rebuilds the **Italian edition only** and
validates its PDF and EPUB. On success, it retains the draft artefacts and SHA-256
checksums as a **private workflow artifact for 14 days**. It does not create tags,
releases or GitHub Pages and it does not modify the tracked copies in `book/it/`.

The maintainer must still inspect the resulting PDF/EPUB, update the tracked files and
the abbreviated checksums in `docs/releases/v1.0.0-it.md`, then run
`make release-package` and `make release-check` on a clean checkout. This automated
build does **not** replace the scientific, copyright or personal attestations below.
`make originalita` requires an actual source corpus in `fonti/` and cannot be
considered passed if that corpus is missing.

## Publishing `v1.0.0-it` (to be done by the maintainer)

The release, its tag and the website are published only with the maintainer's explicit
approval. A full dry run of steps 2–4 and 7 was carried out on 29 October 2026 in a
throwaway clone, without creating anything on GitHub.


1. **Attestations** below confirmed.
2. On an up-to-date, clean `main`:
   ```bash
   make check && make test && make verifica-cronologia
   make release-package      # dist/onion-routing-anatomy-v1.0.0-it/ + ZIP, with SHA256SUMS
   make release-check        # version, notes, checksums, package, tag: must report 0 problems
   ```
3. Tag the commit the files belong to, then push only that tag:
   ```bash
   git tag -a v1.0.0-it -m "Anatomia di Tor 1.0.0, edizione italiana"
   make release-check        # now reports: tag points to the current commit
   git push origin v1.0.0-it
   ```
4. Create the release. With the GitHub CLI:
   ```bash
   cd dist/onion-routing-anatomy-v1.0.0-it
   gh release create v1.0.0-it --verify-tag \
     --title "Anatomia di Tor 1.0.0 — edizione italiana" --notes-file RELEASE-NOTES.md \
     anatomia-di-tor_it_A4.pdf anatomia-di-tor_it.epub anatomia-di-tor_it_7x10.pdf \
     anatomia-di-tor_it_copertina.png LICENSE NOTICE.md SHA256SUMS
   ```
   Or on the web: *Releases → Draft a new release*, tag `v1.0.0-it`, the same title, the text
   of `RELEASE-NOTES.md`, and the same seven files attached. Then download one file from the
   release page and check it with `sha256sum -c SHA256SUMS`.
5. Switch the documents from "in preparation" to "published" in one commit:
   - `website/site.toml`: `published = true`;
   - `README.md`, section *Download*: replace "The GitHub release `v1.0.0-it`, with SHA-256
     checksums, is **in preparation**." with "Download them from the
     [GitHub release `v1.0.0-it`](https://github.com/aleff-github/onion-routing-anatomy/releases/tag/v1.0.0-it),
     with SHA-256 checksums."; section *Scaricare il libro*: replace "La release GitHub
     `v1.0.0-it`, con le impronte SHA-256, è **in preparazione**." with "Si scaricano dalla
     [release GitHub `v1.0.0-it`](https://github.com/aleff-github/onion-routing-anatomy/releases/tag/v1.0.0-it),
     con le impronte SHA-256."; then `python3 scripts/generate_readme_it.py`;
   - `CHANGELOG.md`: heading `## v1.0.0-it — Italian edition 1.0.0 (<date>)`;
   - `book/README.md` and the table at the top of this file: "published on <date>".

   Then `make check` (it now requires the download links on the site and checks that the
   files exist in `book/it/`) and `make release-check` (the tag stays on the earlier commit;
   that is fine as long as `book/it/` and the notes have not changed), commit and push `main`.
6. Website: `make site-publish PUSH=1`, enable Pages on the `gh-pages` branch, then
   `make site-check-online` ([github-pages.md](github-pages.md)).
7. Enable private vulnerability reporting (*Settings → Code security*), see
   [`../../SECURITY.md`](../../SECURITY.md).

## Attestations to confirm before publication

These statements cannot be verified from the repository; they are confirmed personally, or
the documents are corrected, before publication.

- [ ] **Rights.** I hold the rights needed to release the text, figures, cover and code under
  GPL-3.0-or-later — including any passage derived from my bachelor's thesis or earlier study
  material.
- [ ] **First publication.** The work has not been distributed before this publication; if
  copies were given to third parties under other terms, they are listed in `NOTICE.md`.
- [ ] **Story.** The account of the project's origin in `README.md` and on the website
  (study begun for my bachelor's thesis, continued after university, reorganised and extended
  over the years) is accurate.
- [ ] **AI disclosure.** `AI_DISCLOSURE.md` describes the use of AI tools correctly and
  completely; any part of the text I wrote personally is added there.
- [ ] **Approval of the text.** I approve version 1.0.0 for publication, knowing that no
  independent review has taken place (external experts, legal review of chapter 25).
- [ ] **Contact.** Private vulnerability reporting is enabled once the repository is public
  (*Settings → Code security → Private vulnerability reporting*), or another private channel
  is named in `SECURITY.md`.
- [ ] **Patch for tor.** Before sending `docs/it/segnalazioni/0001-exit-connectrefused.patch`
  upstream, the placeholder address in its `From:` line is replaced with the address the
  author wants to use.
