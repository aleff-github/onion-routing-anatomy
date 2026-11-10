#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Sito statico multilingue del libro (GitHub Pages o qualunque hosting statico).

    python3 scripts/build_site.py build          genera build/site/ da website/
    python3 scripts/build_site.py check          controlla build/site/ (lingue, link, SEO, release)
    python3 scripts/build_site.py check-online   controlla il sito pubblicato a base_url

Sorgenti: website/site.toml (configurazione), website/i18n/<lingua>.toml (testi di ogni
lingua, con frammenti HTML), website/static/ (foglio di stile e immagini). Niente
JavaScript, font esterni, cookie o servizi di terze parti.

Nei testi si usano segnaposto fra doppie graffe: {{gh}}, {{blob}}, {{new}}, {{p:story}}
(pagina della stessa lingua), {{asset:copertina.png}}, {{version}}, {{download}}... Un
segnaposto sconosciuto ferma la generazione.
"""
import html
import json
import re
import shutil
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

RADICE = Path(__file__).resolve().parent.parent
WEB = RADICE / "website"
OUT = RADICE / "build" / "site"

# (chiave, percorso relativo alla lingua). L'ordine e' quello del menu.
PAGINE = [("home", ""), ("story", "story/"), ("book", "book/"), ("labs", "labs/"),
          ("languages", "languages/"), ("contribute", "contribute/"), ("ai", "ai/"),
          ("license", "license/"), ("independence", "independence/")]

# Modelli di segnalazione che il sito e il README citano (.github/ISSUE_TEMPLATE/).
MODELLI_ISSUE = ["01-typo.yml", "02-translation.yml", "03-technical-correction.yml",
                 "04-laboratory.yml", "05-documentation.yml", "06-proposal.yml"]


def carica():
    conf = tomllib.loads((WEB / "site.toml").read_text(encoding="utf-8"))
    lingue = {}
    for codice in conf["languages"]:
        lingue[codice] = tomllib.loads(
            (WEB / "i18n" / f"{codice}.toml").read_text(encoding="utf-8"))
    return conf, lingue


def commit_sorgente():
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=RADICE, check=True,
                             capture_output=True, text=True).stdout.strip()
        sporco = subprocess.run(["git", "status", "--porcelain"], cwd=RADICE, check=True,
                                capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None, True
    return sha, bool(sporco)


# --------------------------------------------------------------------------- build

def percorso(lingua, pagina):
    return f"{lingua}/{dict(PAGINE)[pagina]}"


def relativo(da, a):
    """URL relativo dalla pagina `da` (directory, es. 'it/story/') al percorso `a`."""
    profondita = da.count("/")
    return "../" * profondita + a if a else ("../" * profondita or "./")


class Segnaposto:
    def __init__(self, conf, testi, lingua, pagina_corrente, extra):
        self.conf, self.testi, self.lingua = conf, testi, lingua
        self.qui = pagina_corrente
        repo = conf["repo"]
        self.valori = {
            "gh": repo,
            "blob": f"{repo}/blob/{conf['branch']}",
            "tree": f"{repo}/tree/{conf['branch']}",
            "new": f"{repo}/issues/new?template=",
            "choose": f"{repo}/issues/new/choose",
            "issues": f"{repo}/issues",
            "releases": f"{repo}/releases",
            "tag": conf["release"]["tag"],
            **{k: str(v) for k, v in conf["edition"].items()},
            **extra,
        }

    def __call__(self, m):
        nome = m.group(1)
        if nome.startswith("p:"):
            chiave = nome[2:]
            if chiave not in dict(PAGINE):
                raise KeyError(f"pagina sconosciuta: {nome}")
            return relativo(self.qui, percorso(self.lingua, chiave))
        if nome.startswith("asset:"):
            return relativo(self.qui, "assets/" + nome[6:])
        if nome not in self.valori:
            raise KeyError(f"segnaposto sconosciuto: {{{{{nome}}}}}")
        return self.valori[nome]

    def sostituisci(self, testo):
        return re.sub(r"\{\{([a-z0-9_:.\-]+)\}\}", self, testo)


def blocco_download(conf, t, sost):
    d = t["download"]
    rel = conf["release"]
    if not rel["published"]:
        corpo = f'<p>{d["pending"]}</p>'
    else:
        base = f'{conf["repo"]}/releases/download/{rel["tag"]}/'
        corpo = (
            '<ul class="downloads">'
            f'<li><a class="button" href="{base}{rel["pdf"]}">{d["pdf"]}</a></li>'
            f'<li><a class="button" href="{base}{rel["epub"]}">{d["epub"]}</a></li>'
            '</ul>'
            f'<p>{d["published"]}</p>')
    return sost.sostituisci(
        f'<section class="download" aria-labelledby="download"><h2 id="download">{d["title"]}</h2>'
        f'{corpo}</section>')


def head(conf, lingue, t, codice, chiave, qui, titolo, descrizione):
    base = conf["base_url"]
    tm = t["meta"]
    righe = [
        "<!doctype html>",
        "<!-- SPDX-License-Identifier: GPL-3.0-or-later  Copyright (C) 2026 Alessandro Greco -->",
        f'<html lang="{tm["html_lang"]}" dir="ltr">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{html.escape(titolo)}</title>",
        f'<meta name="description" content="{html.escape(descrizione)}">',
        '<meta name="author" content="Alessandro Greco">',
        '<meta name="color-scheme" content="light dark">',
        f'<link rel="canonical" href="{base}{qui}">',
    ]
    for altra, ta in lingue.items():
        righe.append(f'<link rel="alternate" hreflang="{ta["meta"]["hreflang"]}" '
                     f'href="{base}{percorso(altra, chiave)}">')
    x_default = "" if chiave == "home" else percorso(conf["languages"][0], chiave)
    righe.append(f'<link rel="alternate" hreflang="x-default" href="{base}{x_default}">')
    righe += [
        f'<link rel="icon" href="{relativo(qui, "assets/favicon.svg")}" type="image/svg+xml">',
        f'<link rel="stylesheet" href="{relativo(qui, "assets/style.css")}">',
        '<meta property="og:type" content="website">',
        f'<meta property="og:site_name" content="{html.escape(tm["site_name"])}">',
        f'<meta property="og:title" content="{html.escape(titolo)}">',
        f'<meta property="og:description" content="{html.escape(descrizione)}">',
        f'<meta property="og:url" content="{base}{qui}">',
        f'<meta property="og:image" content="{base}assets/og-image.png">',
        '<meta property="og:image:width" content="1200">',
        '<meta property="og:image:height" content="630">',
        f'<meta property="og:image:alt" content="{html.escape(tm["og_image_alt"])}">',
        f'<meta property="og:locale" content="{tm["og_locale"]}">',
    ]
    for altra, ta in lingue.items():
        if altra != codice:
            righe.append(f'<meta property="og:locale:alternate" content="{ta["meta"]["og_locale"]}">')
    righe += ['<meta name="twitter:card" content="summary_large_image">', "</head>"]
    return "\n".join(righe)


def intestazione(conf, lingue, t, codice, chiave, qui):
    ui = t["ui"]
    voci_lingua = []
    for altra, ta in lingue.items():
        attuale = ' aria-current="true"' if altra == codice else ""
        voci_lingua.append(
            f'<li><a href="{relativo(qui, percorso(altra, chiave))}" lang="{ta["meta"]["html_lang"]}" '
            f'hreflang="{ta["meta"]["hreflang"]}"{attuale}>{ta["meta"]["name"]}</a></li>')
    voci_menu = []
    for k, _ in PAGINE:
        attuale = ' aria-current="page"' if k == chiave else ""
        voci_menu.append(f'<li><a href="{relativo(qui, percorso(codice, k))}"{attuale}>'
                         f'{t["nav"][k]}</a></li>')
    return (
        f'<a class="skip" href="#content">{ui["skip"]}</a>\n'
        '<header class="site">\n'
        '<div class="bar">'
        f'<a class="brand" href="{relativo(qui, percorso(codice, "home"))}">'
        f'<img src="{relativo(qui, "assets/favicon.svg")}" alt="" width="28" height="28">'
        f'<span>{t["meta"]["site_name"]}</span></a>\n'
        f'<nav class="lang" aria-label="{ui["lang_label"]}"><ul>{"".join(voci_lingua)}</ul></nav>'
        '</div>\n'
        f'<nav class="sections" aria-label="{ui["nav_label"]}"><ul>{"".join(voci_menu)}</ul></nav>\n'
        '</header>')


def piede(conf, t, qui, sost):
    f = t["footer"]
    return sost.sostituisci(
        '<footer class="site">\n'
        f'<p>{f["edition"]}</p>\n'
        f'<p>{f["independent"]}</p>\n'
        f'<p>{f["privacy"]}</p>\n'
        '</footer>')


def pagina(conf, lingue, codice, chiave, extra):
    t = lingue[codice]
    qui = percorso(codice, chiave)
    p = t["pages"][chiave]
    sost = Segnaposto(conf, t, codice, qui, extra)
    sost.valori["download"] = blocco_download(conf, t, sost) if chiave == "home" else ""
    corpo = sost.sostituisci(p["body"])
    if t["meta"]["html_lang"].startswith("zh"):
        # Un a capo fra due caratteri cinesi diventerebbe uno spazio in alcuni browser.
        corpo = re.sub(r"(?<=[\u3000-\u9fff\uff00-\uffef])\n(?=[\u3000-\u9fff\uff00-\uffef])", "", corpo)
    return "\n".join([
        head(conf, lingue, t, codice, chiave, qui, p["title"], p["description"]),
        "<body>",
        intestazione(conf, lingue, t, codice, chiave, qui),
        f'<main id="content" class="page-{chiave}">',
        corpo.strip(),
        "</main>",
        piede(conf, t, qui, sost),
        "</body>",
        "</html>",
        ""])


def pagina_radice(conf, lingue):
    base = conf["base_url"]
    voci = []
    for codice, t in lingue.items():
        tm = t["meta"]
        voci.append(
            f'<li lang="{tm["html_lang"]}"><a href="{percorso(codice, "home")}" hreflang="{tm["hreflang"]}">'
            f'<strong>{tm["name"]}</strong><span>{tm["chooser"]}</span></a></li>')
    righe = [
        "<!doctype html>",
        "<!-- SPDX-License-Identifier: GPL-3.0-or-later  Copyright (C) 2026 Alessandro Greco -->",
        '<html lang="en" dir="ltr">', "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Onion Routing Anatomy — Anatomia di Tor</title>",
        '<meta name="description" content="A free, open-source technical book on the Tor protocol, '
        'byte by byte, with reproducible laboratories. Choose your language.">',
        '<meta name="author" content="Alessandro Greco">',
        '<meta name="color-scheme" content="light dark">',
        f'<link rel="canonical" href="{base}">',
    ]
    for codice, t in lingue.items():
        righe.append(f'<link rel="alternate" hreflang="{t["meta"]["hreflang"]}" '
                     f'href="{base}{percorso(codice, "home")}">')
    righe += [
        f'<link rel="alternate" hreflang="x-default" href="{base}">',
        '<link rel="icon" href="assets/favicon.svg" type="image/svg+xml">',
        '<link rel="stylesheet" href="assets/style.css">',
        '<meta property="og:type" content="website">',
        '<meta property="og:site_name" content="Onion Routing Anatomy">',
        '<meta property="og:title" content="Onion Routing Anatomy — Anatomia di Tor">',
        '<meta property="og:description" content="A free, open-source technical book on the Tor '
        'protocol, byte by byte, with reproducible laboratories.">',
        f'<meta property="og:url" content="{base}">',
        f'<meta property="og:image" content="{base}assets/og-image.png">',
        '<meta property="og:image:width" content="1200">',
        '<meta property="og:image:height" content="630">',
        '<meta property="og:image:alt" content="Onion Routing Anatomy: an onion cross-section next to the title.">',
        '<meta name="twitter:card" content="summary_large_image">',
        "</head>", "<body>",
        '<main id="content" class="chooser">',
        '<img class="cover" src="assets/copertina.png" width="1600" height="2560" '
        'alt="Cover of «Anatomia di Tor»: a cross-section of an onion with concentric rings, '
        'a radial cut and a purple core.">',
        '<h1>Onion Routing Anatomy <span lang="it">· Anatomia di Tor</span></h1>',
        '<p class="subtitle">Choose your language</p>',
        f'<ul class="languages">{"".join(voci)}</ul>',
        "</main>", "</body>", "</html>", ""]
    return "\n".join(righe)


def pagina_404(conf, lingue):
    bp = conf["base_path"]
    voci = []
    for codice, t in lingue.items():
        tm = t["meta"]
        voci.append(f'<li lang="{tm["html_lang"]}"><a href="{bp}{percorso(codice, "home")}">'
                    f'<strong>{tm["name"]}</strong><span>{t["ui"]["not_found"]}</span></a></li>')
    return "\n".join([
        "<!doctype html>",
        '<html lang="en" dir="ltr">', "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Page not found — Onion Routing Anatomy</title>",
        '<meta name="robots" content="noindex">',
        '<meta name="color-scheme" content="light dark">',
        f'<link rel="icon" href="{bp}assets/favicon.svg" type="image/svg+xml">',
        f'<link rel="stylesheet" href="{bp}assets/style.css">',
        "</head>", "<body>",
        '<main id="content" class="chooser">',
        "<h1>404</h1>",
        '<p class="subtitle">Page not found</p>',
        f'<ul class="languages">{"".join(voci)}</ul>',
        "</main>", "</body>", "</html>", ""])


def sitemap(conf, lingue):
    base = conf["base_url"]
    righe = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" '
             'xmlns:xhtml="http://www.w3.org/1999/xhtml">']

    def alternative(chiave):
        out = [f'    <xhtml:link rel="alternate" hreflang="{t["meta"]["hreflang"]}" '
               f'href="{base}{percorso(c, chiave)}"/>' for c, t in lingue.items()]
        x = "" if chiave == "home" else percorso(conf["languages"][0], chiave)
        out.append(f'    <xhtml:link rel="alternate" hreflang="x-default" href="{base}{x}"/>')
        return out

    righe += ["  <url>", f"    <loc>{base}</loc>", *alternative("home"), "  </url>"]
    for chiave, _ in PAGINE:
        for codice in lingue:
            righe += ["  <url>", f"    <loc>{base}{percorso(codice, chiave)}</loc>",
                      *alternative(chiave), "  </url>"]
    righe.append("</urlset>")
    return "\n".join(righe) + "\n"


def build():
    conf, lingue = carica()
    errori = controlla_testi(conf, lingue)
    if errori:
        for e in errori:
            print("website/i18n:", e)
        sys.exit(1)
    sha, sporco = commit_sorgente()
    corto = (sha or "sconosciuto")[:7] + ("+" if sporco else "")
    extra = {"commit": corto,
             "commit_url": f"{conf['repo']}/commit/{sha}" if sha else conf["repo"]}
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    shutil.copytree(WEB / "static" / "assets", OUT / "assets")
    shutil.copy(WEB / "static" / "style.css", OUT / "assets" / "style.css")
    for codice in lingue:
        for chiave, _ in PAGINE:
            dest = OUT / percorso(codice, chiave) / "index.html"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(pagina(conf, lingue, codice, chiave, extra), encoding="utf-8")
    (OUT / "index.html").write_text(pagina_radice(conf, lingue), encoding="utf-8")
    (OUT / "404.html").write_text(pagina_404(conf, lingue), encoding="utf-8")
    (OUT / "sitemap.xml").write_text(sitemap(conf, lingue), encoding="utf-8")
    (OUT / "robots.txt").write_text(
        f"User-agent: *\nAllow: /\n\nSitemap: {conf['base_url']}sitemap.xml\n", encoding="utf-8")
    # Pubblicazione da branch: i file si servono cosi' come sono, senza Jekyll.
    (OUT / ".nojekyll").write_text("", encoding="utf-8")
    (OUT / "version.json").write_text(json.dumps({
        "edition": conf["edition"]["version"], "language": conf["edition"]["language"],
        "release": conf["release"]["tag"], "release_published": conf["release"]["published"],
        "source_commit": sha, "source_dirty": sporco}, indent=2) + "\n", encoding="utf-8")
    n = sum(1 for _ in OUT.rglob("*.html"))
    print(f"Sito generato in {OUT.relative_to(RADICE)}/: {n} pagine HTML, "
          f"{len(lingue)} lingue, sorgente {corto}")
    if sporco:
        print("Attenzione: modifiche non registrate; il sito non corrisponde a un commit.")


# --------------------------------------------------------------------------- check

def appiattisci(d, prefisso=""):
    for k, v in d.items():
        nome = f"{prefisso}{k}"
        if isinstance(v, dict):
            yield from appiattisci(v, nome + ".")
        else:
            yield nome, v


def controlla_testi(conf, lingue):
    """Stesse chiavi in ogni lingua, nessun testo vuoto, nessun testo lasciato in inglese."""
    errori = []
    riferimento = dict(appiattisci(lingue[conf["languages"][0]]))
    # Valori che restano uguali per scelta (nomi propri, sigle).
    uguali_ammessi = {"meta.hreflang"}
    for codice, t in lingue.items():
        valori = dict(appiattisci(t))
        for k in sorted(set(riferimento) - set(valori)):
            errori.append(f"{codice}: manca la chiave {k}")
        for k in sorted(set(valori) - set(riferimento)):
            errori.append(f"{codice}: chiave in piu' {k}")
        for k, v in valori.items():
            if not str(v).strip():
                errori.append(f"{codice}: testo vuoto in {k}")
            if (codice != conf["languages"][0] and k not in uguali_ammessi
                    and v == riferimento.get(k) and len(str(v)) > 24):
                errori.append(f"{codice}: {k} e' identico all'inglese (non tradotto?)")
        for chiave, _ in PAGINE:
            if chiave not in t.get("pages", {}):
                errori.append(f"{codice}: manca la pagina {chiave}")
    return errori


class Analisi(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids, self.link, self.risorse, self.meta, self.alternate = set(), [], [], {}, {}
        self.lang = None
        self.titolo, self._in_titolo = "", False
        self.h1, self.script, self.img_senza_alt, self.canonical = 0, 0, 0, None
        self.lingue_menu = 0
        self._in_lang_nav = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.add(a["id"])
        if tag == "html":
            self.lang = a.get("lang")
        elif tag == "title":
            self._in_titolo = True
        elif tag == "h1":
            self.h1 += 1
        elif tag == "script":
            self.script += 1
        elif tag == "img":
            self.risorse.append(a.get("src", ""))
            if "alt" not in a:
                self.img_senza_alt += 1
        elif tag == "a" and "href" in a:
            self.link.append(a["href"])
            if self._in_lang_nav:
                self.lingue_menu += 1
        elif tag == "nav" and "lang" in (a.get("class") or "").split():
            self._in_lang_nav = True
        elif tag == "link":
            rel = a.get("rel", "")
            if rel == "canonical":
                self.canonical = a.get("href")
            elif rel == "alternate" and "hreflang" in a:
                self.alternate[a["hreflang"]] = a.get("href")
            elif rel in ("stylesheet", "icon"):
                self.risorse.append(a.get("href", ""))
        elif tag == "meta":
            chiave = a.get("property") or a.get("name")
            if chiave:
                self.meta[chiave] = a.get("content", "")

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_titolo = False
        elif tag == "nav":
            self._in_lang_nav = False

    def handle_data(self, data):
        if self._in_titolo:
            self.titolo += data


def file_di(url_rel, pagina_file):
    """File locale di un URL relativo, o None se esce dal sito."""
    destinazione = (pagina_file.parent / url_rel).resolve()
    if OUT.resolve() not in destinazione.parents and destinazione != OUT.resolve():
        return None
    if url_rel.endswith("/") or destinazione.is_dir():
        destinazione = destinazione / "index.html"
    return destinazione


def controlla_link_repository(conf, url):
    """I link alla repository devono puntare a file, cartelle e modelli che esistono."""
    repo = conf["repo"]
    if not url.startswith(repo):
        return None
    resto = url[len(repo):]
    for prefisso in (f"/blob/{conf['branch']}/", f"/tree/{conf['branch']}/"):
        if resto.startswith(prefisso):
            locale = RADICE / resto[len(prefisso):].split("#")[0]
            return None if locale.exists() else f"file assente nella repository: {locale.relative_to(RADICE)}"
    m = re.match(r"/issues/new\?template=([^&#]+)", resto)
    if m:
        modello = RADICE / ".github" / "ISSUE_TEMPLATE" / m.group(1)
        return None if modello.exists() else f"modello di issue assente: {m.group(1)}"
    if resto.startswith("/releases/download/"):
        if not conf["release"]["published"]:
            return "link di download a una release non ancora pubblicata"
        nome = resto.rsplit("/", 1)[-1]
        locale = RADICE / "book" / conf["edition"]["language"] / nome
        return None if locale.exists() else f"file della release assente in book/: {nome}"
    if resto in ("", "/", "/issues", "/issues/new/choose", "/releases", "/security/advisories/new") \
            or resto.startswith(("/commit/", "/releases/tag/")):
        return None
    return f"link alla repository non riconosciuto: {url}"


def check():
    conf, lingue = carica()
    errori = [f"website/i18n: {e}" for e in controlla_testi(conf, lingue)]
    if not OUT.is_dir():
        sys.exit("build/site/ non esiste: esegui prima `python3 scripts/build_site.py build`")
    base = conf["base_url"]
    pagine_html = sorted(OUT.rglob("*.html"))
    analisi = {}
    for f in pagine_html:
        a = Analisi()
        a.feed(f.read_text(encoding="utf-8"))
        analisi[f] = a
    titoli = {}
    attese = {percorso(c, k): (c, k) for c in lingue for k, _ in PAGINE}
    for rel, (codice, chiave) in attese.items():
        f = OUT / rel / "index.html"
        if f not in analisi:
            errori.append(f"{rel}: pagina mancante")
            continue
        a = analisi[f]
        t = lingue[codice]
        if a.lang != t["meta"]["html_lang"]:
            errori.append(f"{rel}: lang={a.lang!r}, atteso {t['meta']['html_lang']!r}")
        if a.h1 != 1:
            errori.append(f"{rel}: {a.h1} elementi h1 (atteso 1)")
        if a.titolo in titoli:
            errori.append(f"{rel}: titolo uguale a {titoli[a.titolo]}")
        titoli[a.titolo] = rel
        descr = a.meta.get("description", "")
        # Una frase cinese dice in 40 caratteri cio' che in inglese ne richiede 120.
        minimo = 30 if codice.startswith("zh") else 50
        if not minimo <= len(descr) <= 200:
            errori.append(f"{rel}: meta description di {len(descr)} caratteri")
        if a.canonical != base + rel:
            errori.append(f"{rel}: canonical {a.canonical}")
        attese_alt = {lingue[c]["meta"]["hreflang"]: base + percorso(c, chiave) for c in lingue}
        attese_alt["x-default"] = base + ("" if chiave == "home" else percorso(conf["languages"][0], chiave))
        if a.alternate != attese_alt:
            errori.append(f"{rel}: hreflang non coerenti: {a.alternate}")
        for m in ("og:title", "og:description", "og:url", "og:image", "og:locale", "twitter:card"):
            if not a.meta.get(m):
                errori.append(f"{rel}: manca {m}")
        if a.lingue_menu != len(lingue):
            errori.append(f"{rel}: il selettore ha {a.lingue_menu} lingue")
    for f, a in analisi.items():
        rel = f.relative_to(OUT).as_posix()
        if a.script:
            errori.append(f"{rel}: contiene <script>")
        if a.img_senza_alt:
            errori.append(f"{rel}: {a.img_senza_alt} immagini senza alt")
        for r in a.risorse:
            if urlsplit(r).scheme:
                errori.append(f"{rel}: risorsa esterna {r}")
        for href in a.link + a.risorse:
            parti = urlsplit(href)
            if parti.scheme in ("http", "https"):
                problema = controlla_link_repository(conf, href)
                if problema:
                    errori.append(f"{rel}: {problema}")
                continue
            if parti.scheme in ("mailto",):
                continue
            if href.startswith("/"):
                if f.name != "404.html" or not href.startswith(conf["base_path"]):
                    errori.append(f"{rel}: percorso assoluto {href} (non funziona sotto un prefisso)")
                    continue
                destinazione = OUT / href[len(conf["base_path"]):].split("#")[0]
                if href.endswith("/"):
                    destinazione = destinazione / "index.html"
            elif parti.path:
                destinazione = file_di(parti.path, f)
            else:
                destinazione = f
            if destinazione is None or not destinazione.exists():
                errori.append(f"{rel}: link interrotto {href}")
                continue
            if parti.fragment and destinazione.suffix == ".html":
                ids = analisi[destinazione].ids if destinazione in analisi else set()
                if parti.fragment not in ids:
                    errori.append(f"{rel}: ancora inesistente {href}")
    # File di servizio.
    for nome in (".nojekyll", "404.html", "robots.txt", "sitemap.xml", "version.json",
                 "assets/style.css", "assets/favicon.svg", "assets/og-image.png",
                 "assets/copertina.png"):
        if not (OUT / nome).exists():
            errori.append(f"manca {nome}")
    mappa = (OUT / "sitemap.xml").read_text(encoding="utf-8") if (OUT / "sitemap.xml").exists() else ""
    for rel in [""] + list(attese):
        if f"<loc>{base}{rel}</loc>" not in mappa:
            errori.append(f"sitemap.xml: manca {base}{rel}")
    # Corrispondenza fra sito ed edizione del libro.
    makefile = (RADICE / "Makefile").read_text(encoding="utf-8")
    m = re.search(r"^VERSIONE \?= (\S+)", makefile, re.M)
    if not m or m.group(1) != conf["edition"]["version"]:
        errori.append("website/site.toml: edition.version diverso da VERSIONE nel Makefile")
    if conf["release"]["tag"] not in (RADICE / "CHANGELOG.md").read_text(encoding="utf-8"):
        errori.append(f"CHANGELOG.md: nessuna voce per {conf['release']['tag']}")
    for modello in MODELLI_ISSUE:
        if not (RADICE / ".github" / "ISSUE_TEMPLATE" / modello).exists():
            errori.append(f".github/ISSUE_TEMPLATE/{modello}: assente")
    for e in errori:
        print(e)
    print(f"\nSito: {len(analisi)} pagine HTML, {len(lingue)} lingue, "
          f"release {'pubblicata' if conf['release']['published'] else 'in preparazione'}: "
          f"{len(errori)} problemi")
    return 1 if errori else 0


def check_online():
    """Da eseguire dopo l'attivazione di GitHub Pages: ogni URL della sitemap risponde e
    dichiara il canonical atteso."""
    conf, _ = carica()
    base = conf["base_url"]
    errori = 0
    try:
        with urllib.request.urlopen(base + "sitemap.xml", timeout=30) as r:
            mappa = r.read().decode("utf-8")
    except (urllib.error.URLError, OSError) as e:
        print(f"{base}sitemap.xml: non raggiungibile ({e})")
        return 2
    indirizzi = re.findall(r"<loc>([^<]+)</loc>", mappa)
    for url in indirizzi:
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                testo = r.read().decode("utf-8")
        except (urllib.error.URLError, OSError) as e:
            print(f"{url}: {e}")
            errori += 1
            continue
        if f'<link rel="canonical" href="{url}">' not in testo:
            print(f"{url}: canonical diverso dall'indirizzo pubblicato")
            errori += 1
    for nome in ("assets/style.css", "assets/og-image.png", "robots.txt"):
        try:
            urllib.request.urlopen(urljoin(base, nome), timeout=30).close()
        except (urllib.error.URLError, OSError) as e:
            print(f"{base}{nome}: {e}")
            errori += 1
    try:
        urllib.request.urlopen(base + "pagina-inesistente/", timeout=30).close()
        print("pagina inesistente: risposta 200 invece di 404")
        errori += 1
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print(f"pagina inesistente: risposta {e.code}")
            errori += 1
    print(f"{len(indirizzi)} indirizzi controllati su {base}: {errori} problemi")
    return 1 if errori else 0


if __name__ == "__main__":
    comando = sys.argv[1] if len(sys.argv) > 1 else "build"
    if comando == "build":
        build()
    elif comando == "check":
        sys.exit(check())
    elif comando == "check-online":
        sys.exit(check_online())
    else:
        sys.exit(__doc__)
