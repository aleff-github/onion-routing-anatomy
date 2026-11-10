# Publishing the website on GitHub Pages

The website is published **from a branch** (`gh-pages`, folder `/`), prepared locally by
`scripts/publish_site.sh`. The repository contains no GitHub Actions workflow.

> **Status (29 October 2026): not published.** The repository is private and GitHub Pages is
> not enabled. The address in `website/site.toml`
> (`https://aleff-github.github.io/onion-routing-anatomy/`) is the expected one for a project
> site and has not been verified. Nothing in this document has been run against GitHub yet.

## Requirements (GitHub documentation, checked on 29 October 2026)

- With GitHub Free, Pages is available only for **public** repositories (private
  repositories need GitHub Pro, Team or Enterprise). Publishing the site therefore follows
  the decision to make the repository public.
- Publishing source: *Settings → Pages → Build and deployment → Deploy from a branch*; the
  branch must already exist, and the folder is either `/` (root) or `/docs`.
- A project site is served at `https://<owner>.github.io/<repository>/`.
- Branch publishing normally runs Jekyll; the generated site contains an empty `.nojekyll`
  file so files are served as they are. `404.html` at the root is used for missing pages.
- Even with branch publishing, GitHub deploys the site with its own internal
  *pages build and deployment* run, shown in the Actions tab. It is not a workflow of this
  repository and needs no configuration.
- Limits: published site at most 1 GB, soft bandwidth limit of 100 GB per month, soft limit
  of 10 builds per hour. The generated site is well under 1 MB.
- A Pages site is public on the internet. GitHub logs visitors' IP addresses (stated on the
  site's *Independence* page).

Sources: docs.github.com — *About GitHub Pages*, *Configuring a publishing source for your
GitHub Pages site*, *GitHub Pages limits*, *Creating a custom 404 page*.

## First publication (to be done by the maintainer)

1. Make sure `main` is pushed and the working tree is clean.
2. `make site-check` — must report 0 problems.
3. `make site-publish` — builds, checks and records a commit on the **local** `gh-pages`
   branch. The commit message names the source commit and the edition. Look at it with
   `git log gh-pages -1` and, if you like, `git show --stat gh-pages`.
4. `make site-publish PUSH=1` — sends `gh-pages` to GitHub.
5. On GitHub: *Settings → Pages → Deploy from a branch*, branch `gh-pages`, folder `/ (root)`,
   *Save*. Optionally tick *Enforce HTTPS* once it becomes available.
6. When GitHub shows the address, run `make site-check-online`: every address in the sitemap
   must answer and declare itself as canonical, and a missing page must return 404.
7. If the real address differs (for example a custom domain), set `base_url` and `base_path`
   in `website/site.toml`, commit, and repeat from step 2.

## Updating the site

Edit `website/`, commit, then `make site-publish PUSH=1`. Each commit on `gh-pages`
records the `main` commit it was generated from, and the footer of every page shows it,
together with the edition and the release tag.

**When release `v1.0.0-it` is published:** set `release.published = true` in
`website/site.toml`, commit, republish. `make site-check` then requires the download links
and verifies that the files they name exist in `book/it/`; `make site-check-online` can be
run again afterwards.

## Search engines

- `sitemap.xml` lists every page with its language alternates.
- `robots.txt` is generated, but crawlers read it only at the root of a host: on a project
  site (`aleff-github.github.io/onion-routing-anatomy/`) it is ignored, and the sitemap has
  to be submitted directly (for example in Google Search Console). With a custom domain it
  works as is.
- Social preview: `assets/og-image.png` (1200×630), referenced with an absolute URL built
  from `base_url`.

## Removing the site

*Settings → Pages → Unpublish site*, or delete the `gh-pages` branch.
