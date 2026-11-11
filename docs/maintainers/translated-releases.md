# Publishing the translated editions

The Italian GitHub release `v1.0.0-it` remains unchanged. The four translated
editions use the tags `v1.0.0-en`, `v1.0.0-es`, `v1.0.0-ru` and
`v1.0.0-zh-Hans`. They are ordinary releases, **not pre-releases**;
the descriptions explicitly disclose that independent linguistic review has
not taken place.

The publishing script uses the **already committed** PDF A4, EPUB 3 and
cover images in `book/<language>/`, plus `LICENSE`, `NOTICE.md`,
the localized release notes and generated SHA-256 checksums. It never runs
a new book build and never starts GitHub Actions.

## Run on a computer with GitHub CLI

Install Git, Python 3.10+ and `gh`, then authenticate using `gh auth login`
with a GitHub account that can create releases.

```sh
git clone https://github.com/aleff-github/onion-routing-anatomy.git
cd onion-routing-anatomy
python3 scripts/publish_translated_releases.py
python3 scripts/publish_translated_releases.py --publish
```

If you already have a clone, update `main` first using
`git pull --ff-only`. The first command performs checks only; the second
publishes the missing releases. It checks the repository, clean branch,
remote HEAD, GitHub authentication, release/tag collisions and asset
presence, then stages each language's files and computes checksums.
Existing releases are skipped without modification. The script uses the
exact checked commit as each new tag's target; no tag is force-moved.

GitHub CLI will upload each release's assets directly to GitHub Releases.
No GitHub Actions workflow artifacts are created or retained. If a command
fails after one or more releases are created, fix the cause and rerun:
already-created releases are skipped, not overwritten. A partial draft left
by the GitHub API must be checked manually before retrying.

After publication, check each release page and download a set of assets
to verify `sha256sum -c SHA256SUMS`. Then update README and website
references from repository downloads to official release URLs, and publish
a refreshed `gh-pages` snapshot. Do not claim that independent linguistic
or scientific validation took place.
