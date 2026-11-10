#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Controlli sugli EPUB delle cinque edizioni, oltre a EPUBCheck.

EPUBCheck verifica che il pacchetto sia valido, non che il libro sia completo: un
carattere scartato da tex4ht o una formula senza testo alternativo passano
inosservati. Per ogni edizione questo script controlla:

- EPUBCheck: 0 errori e 0 avvisi (se `epubcheck` o `java -jar /usr/bin/epubcheck`
  sono disponibili; altrimenti lo dichiara e fallisce);
- metadati OPF: identificatore urn:uuid, lingua, copertina, diritti, nessuna dc:date
  (la data di pubblicazione non esiste ancora);
- frontespizio, colophon (prima edizione, versione 1.0.0, GPL) e indice navigabile;
- formule display: tante immagini quante nei sorgenti, ciascuna con un testo
  alternativo curato (source/shared/epub/epub-filters.lua);
- figure con testo alternativo, tabelle presenti, nessun rimando irrisolto ("??");
- completezza del testo rispetto al PDF della stessa edizione: ogni parola (ogni
  carattere cinese) del PDF deve comparire nell'EPUB, salvo quelle che stanno solo
  dentro le figure (immagini SVG nell'EPUB); le virgolette devono esserci tutte.

    python3 scripts/check_epub.py [it en es ru zh-Hans]

Richiede pdftotext (poppler-utils). I file si generano prima con make book-epub e
make book-pdf (italiano) e con make -C source/<lingua> pdf epub (traduzioni).
"""
from __future__ import annotations

import html
import re
import shutil
import subprocess
import sys
import unicodedata
import zipfile
from collections import Counter
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
SORGENTI = RADICE / "source"

EDIZIONI = {
    "it": dict(virgolette=(("«", "»"), ("“", "”")), epub=RADICE / "book/it/anatomia-di-tor_it.epub", pdf=RADICE / "book/it/anatomia-di-tor_it_A4.pdf",
               lingua="it", indice="Indice analitico", colophon="Prima edizione, versione 1.0.0",
               cartelle=("capitoli", "appendici", "figure")),
    "en": dict(virgolette=(("“", "”"), ("‘", "’")), epub=SORGENTI / "en/epub.epub", pdf=SORGENTI / "en/main.pdf", lingua="en",
               indice="Index", colophon="First edition, version 1.0.0",
               cartelle=("chapters", "appendices", "figures")),
    "es": dict(virgolette=(("«", "»"), ("“", "”")), epub=SORGENTI / "es/epub.epub", pdf=SORGENTI / "es/main.pdf", lingua="es",
               indice="Índice analítico", colophon="Primera edición, versión 1.0.0",
               cartelle=("capitulos", "apendices", "figuras")),
    "ru": dict(virgolette=(("«", "»"), ("„", "“")), epub=SORGENTI / "ru/epub.epub", pdf=SORGENTI / "ru/main.pdf", lingua="ru",
               indice="Предметный указатель", colophon="Первое издание, версия 1.0.0",
               cartelle=("главы", "приложения", "рисунки")),
    "zh-Hans": dict(virgolette=(("“", "”"), ("‘", "’")), epub=SORGENTI / "zh-Hans/epub.epub", pdf=SORGENTI / "zh-Hans/main.pdf", lingua="zh-Hans",
                    indice="索引", colophon="第一版，版本 1.0.0",
                    cartelle=("章节", "附录", "图")),
}

CJK = re.compile(r"[\u3400-\u9fff\uf900-\ufaff]")


def senza_commenti(testo: str) -> str:
    return "\n".join(re.sub(r"(?<!\\)%.*", "", r) for r in testo.split("\n"))


def sorgenti(conf, cartella_indice: int) -> list[Path]:
    base = SORGENTI / lingua_dir(conf)
    return sorted((base / conf["cartelle"][cartella_indice]).rglob("*.tex"))


def lingua_dir(conf) -> str:
    return next(k for k, v in EDIZIONI.items() if v is conf)


DISPLAY = re.compile(r"\\\[(.*?)\\\]|\\begin\{(gather\*|equation\*?|align\*?)\}(.*?)\\end\{\2\}", re.S)


def formule_display_sorgenti(conf) -> list[str]:
    out = []
    for f in sorgenti(conf, 0) + sorgenti(conf, 1):
        t = senza_commenti(f.read_text(encoding="utf-8"))
        t = re.sub(r"\\begin\{lstlisting\}.*?\\end\{lstlisting\}", "", t, flags=re.S)
        out += [m.group(1) or m.group(3) for m in DISPLAY.finditer(t)]
    return out


def formule_display(conf) -> int:
    return len(formule_display_sorgenti(conf))


def sorgente_display(conf) -> str:
    """Testo delle formule display senza i comandi LaTeX (\\mathrm{AES}_K -> AES K)."""
    testo = "\n".join(formule_display_sorgenti(conf))
    testo = re.sub(r"\\[a-zA-Z]+", " ", testo)
    return re.sub(r"[{}_^]", "", testo) + "\n" + re.sub(r"[{}_^\\]", " ", testo)


def testo_figure(conf) -> str:
    """Sorgenti delle figure (con i testi alternativi \\altfig)."""
    return "\n".join(f.read_text(encoding="utf-8") for f in sorgenti(conf, 2))


def tabelle_sorgenti(conf) -> str:
    """Testo di tabelle e listati dei sorgenti: il PDF li legge colonna per colonna."""
    out = []
    for f in sorgenti(conf, 0) + sorgenti(conf, 1):
        t = senza_commenti(f.read_text(encoding="utf-8"))
        out += [m.group(0) for m in re.finditer(
            r"\\begin\{(tabular|tabularx|longtable|lstlisting)\}.*?\\end\{\1\}", t, re.S)]
    return "\n".join(out)


def disegno_figure(conf) -> str:
    """Testo disegnato nelle figure: nell'EPUB e' dentro immagini SVG. Senza \\altfig
    (che nell'EPUB e' testo alternativo, non nel PDF) e senza commenti."""
    testo = senza_commenti(testo_figure(conf))
    return "\n".join(r for r in testo.split("\n") if not r.lstrip().startswith("\\altfig{"))


def leggi_epub(percorso: Path):
    z = zipfile.ZipFile(percorso)
    opf = z.read("OEBPS/content.opf").decode("utf-8")
    pagine = {n: z.read(n).decode("utf-8") for n in z.namelist() if n.endswith(".xhtml")}
    return z, opf, pagine


def solo_testo(xhtml: str) -> str:
    xhtml = re.sub(r"<(script|style)\b.*?</\1>", " ", xhtml, flags=re.S)
    # Gli elementi in linea non separano le parole ("p<sub>f</sub>" e' "pf", come nel PDF).
    xhtml = re.sub(r"</?(?:span|sub|sup|a|em|strong|b|i|code|small|tt)\b[^>]*>", "", xhtml)
    return html.unescape(re.sub(r"<[^>]+>", " ", xhtml))


def testo_pdf(percorso: Path) -> str:
    if not shutil.which("pdftotext"):
        raise SystemExit("pdftotext non trovato (pacchetto poppler-utils)")
    r = subprocess.run(["pdftotext", "-enc", "UTF-8", str(percorso), "-"], capture_output=True, check=True)
    return r.stdout.decode("utf-8")


# Parola spezzata dal trattino a fine riga; se la riga e' l'ultima della pagina, fra le
# due parti ci sono la testatina e il numero della pagina seguente ("so-" | "CAPITOLO 2.
# LE RADICI..." | "10" | "prattutto").
A_CAPO = re.compile(r"([^\W\d_]+)-[ \t]*\n[ \t\n]*(?:\f(?:\d+\s*\n\s*)?[^\n]*\n\s*(?:\d+\s*\n\s*)?)?([^\W\d_]+)")


def parole(testo: str, vocabolario: Counter | None = None) -> Counter:
    """Parole (in minuscolo) e caratteri cinesi del testo.

    Nel testo del PDF una parola spezzata a fine riga ("anun-\n\nciarse") si ricompone
    solo se la forma unita compare nell'EPUB; altrimenti il trattino era vero
    ("advisory-\nrelay") e restano le due parti.
    """
    testo = unicodedata.normalize("NFKC", testo).replace("\u00ad", "")
    if vocabolario is not None:
        def unisci(m):
            unita = (m.group(1) + m.group(2)).lower()
            return m.group(1) + m.group(2) if unita in vocabolario else m.group(1) + " " + m.group(2)
        testo = re.sub(A_CAPO, unisci, testo)
    c = Counter(w.lower() for w in re.findall(r"[^\W\d_]{2,}", CJK.sub(" ", testo)))
    c.update(CJK.findall(testo))
    return c


def sequenza(testo: str, vocabolario: Counter | None = None) -> list[str]:
    """Parole e caratteri cinesi nell'ordine del testo, con i criteri di parole()."""
    testo = unicodedata.normalize("NFKC", testo).replace("­", "").lower()
    if vocabolario is not None:
        testo = re.sub(A_CAPO,
                       lambda m: m.group(1) + m.group(2) if (m.group(1) + m.group(2)) in vocabolario
                       else m.group(1) + " " + m.group(2), testo)
    # Lettere e cifre in gettoni separati: nei listati dell'EPUB il numero di riga resta
    # attaccato al codice ("11s.sendall") quando si tolgono i tag di evidenziazione.
    parole_ = re.findall(r"[\u3400-\u9fff\uf900-\ufaff]|[^\W\d_\u3400-\u9fff\uf900-\ufaff]+|\d+", testo)
    # I numeri di riga dei listati e di pagina (fino a tre cifre) stanno in punti diversi
    # nel PDF e nell'EPUB: non entrano nel confronto delle sequenze.
    return [w for w in parole_ if not (w.isdigit() and len(w) <= 3)]


def conta_enquote(conf) -> tuple[int, int]:
    """\\enquote esterne e annidate (dentro un'altra \\enquote) di capitoli e appendici."""
    esterne = annidate = 0
    for f in sorgenti(conf, 0) + sorgenti(conf, 1):
        t = senza_commenti(f.read_text(encoding="utf-8"))
        t = re.sub(r"\\begin\{lstlisting\}.*?\\end\{lstlisting\}", "", t, flags=re.S)
        aperte: list[int] = []       # livello di graffe a cui si chiude ogni \\enquote aperta
        livello, i = 0, 0
        while i < len(t):
            if t.startswith("\\enquote{", i):
                if aperte:
                    annidate += 1
                else:
                    esterne += 1
                livello += 1
                aperte.append(livello)
                i += len("\\enquote{")
            elif t[i] == "\\":
                i += 2
            else:
                if t[i] == "{":
                    livello += 1
                elif t[i] == "}":
                    if aperte and aperte[-1] == livello:
                        aperte.pop()
                    livello -= 1
                i += 1
    return esterne, annidate


def senza_indice_generale(pdf: str) -> str:
    """Toglie le pagine dell'indice generale (fra le prime 20): l'EPUB ha l'indice nel
    documento di navigazione, con i titoli in un ordine e una forma diversi."""
    pagine_pdf = pdf.split("\f")
    for k, pagina in enumerate(pagine_pdf[:20]):
        righe = [r for r in pagina.split("\n") if r.strip()]
        voci = [r for r in righe if re.search(r"(\.\s?){4,}", r) or re.fullmatch(r"\s*[\dxivlc]+\s*", r)]
        if righe and len(voci) >= 0.3 * len(righe):
            pagine_pdf[k] = ""
    return "\f".join(pagine_pdf)


# Comandi il cui argomento non e' testo del libro (rimandi, etichette, indice) o genera
# un testo che non sta nei sorgenti: si sostituiscono con un separatore.
SENZA_TESTO = ("cref", "Cref", "ref", "pageref", "eqref", "cite", "label", "index", "input",
               "include", "includegraphics", "altfig", "proposta", "hyperref", "hspace", "vspace",
               "setlength", "addtocounter", "setcounter", "phantomsection", "addcontentsline",
               "markboth", "markright", "chaptermark", "sectionmark", "thispagestyle", "pagestyle", "newpage", "clearpage",
               "cleardoublepage", "bibliography", "printbibliography", "printindex", "url")
AMBIENTI_ESCLUSI = ("lstlisting", "verbatim", "tikzpicture", "bytefield", "equation", "equation*",
                    "align", "align*", "gather", "gather*", "multline", "multline*")
SEPARATORE = " \u2016 "


def testo_sorgente(tex: str) -> str:
    """Testo leggibile di un file LaTeX, con un separatore dove manca del testo."""
    t = senza_commenti(tex)
    for amb in AMBIENTI_ESCLUSI:
        t = re.sub(r"\\begin\{" + re.escape(amb) + r"\}.*?\\end\{" + re.escape(amb) + r"\}",
                   SEPARATORE, t, flags=re.S)
    t = re.sub(r"\\\[.*?\\\]", SEPARATORE, t, flags=re.S)
    t = re.sub(r"\\\(.*?\\\)", SEPARATORE, t, flags=re.S)
    t = re.sub(r"(?<!\\)\$[^$]*\$", SEPARATORE, t)
    t = re.sub(r"\\(" + "|".join(SENZA_TESTO) + r")\*?(\[[^\]]*\])*(\{[^{}]*\})*", SEPARATORE, t)
    t = re.sub(r"\\(begin|end)\{[^}]*\}(\[[^\]]*\])?(\{[^{}]*\})?", SEPARATORE, t)
    t = t.replace("\\\\", SEPARATORE).replace("\\_", "_").replace("\\%", "%").replace("\\&", SEPARATORE)
    t = t.replace("\\-", "").replace("~", " ").replace("\\,", " ").replace("&", SEPARATORE)
    t = re.sub(r"\\item(\[[^\]]*\])?", SEPARATORE + r" \1 ", t)
    t = re.sub(r"\\[a-zA-Z@]+\*?(\[[^\]]*\])?", SEPARATORE, t)
    t = re.sub(r"\\.", " ", t)
    return t.replace("{", " ").replace("}", " ")


def frasi_mancanti(conf, epub: str, vocabolario: Counter | None = None) -> list[str]:
    """Frasi dei sorgenti (capitoli e appendici) di cui l'EPUB non contiene il testo.

    Per ogni frase si prende un tratto di 4 parole consecutive (6 caratteri in cinese)
    senza formule, rimandi o comandi in mezzo, e lo si cerca nell'EPUB. Una frase o
    un paragrafo scartati dalla conversione non hanno riscontro.
    """
    cinese = conf["lingua"].startswith("zh")
    n = 6 if cinese else 4
    e = sequenza(epub, vocabolario)
    finestre = {tuple(e[i:i + n]) for i in range(len(e) - n + 1)}
    mancanti = []
    for f in sorgenti(conf, 0) + sorgenti(conf, 1):
        testo = testo_sorgente(f.read_text(encoding="utf-8"))
        for pezzo in re.split(r"\u2016|[.;:!?\u3002\uff1b\uff1a\uff01\uff1f]\s", testo):
            g = sequenza(pezzo)
            if cinese:
                # tratti di soli caratteri cinesi consecutivi
                corse, corrente = [], []
                for w in g:
                    if "\u3400" <= w[0] <= "\ufaff":
                        corrente.append(w)
                    else:
                        corse.append(corrente)
                        corrente = []
                corse.append(corrente)
                g = max(corse, key=len)
            if len(g) < n:
                continue
            k = (len(g) - n) // 2
            if tuple(g[k:k + n]) not in finestre:
                mancanti.append(f"{f.name}: " + (" ".join(pezzo.split())))
        # Listati: ogni riga di almeno 3 gettoni deve comparire, intera, nell'EPUB.
        tex = senza_commenti(f.read_text(encoding="utf-8"))
        for listato in re.findall(r"\\begin\{lstlisting\}(?:\[[^\]]*\])?(.*?)\\end\{lstlisting\}", tex, re.S):
            for riga in listato.split("\n"):
                g = sequenza(riga)
                if len(g) >= 3 and tuple(g[:3]) not in finestre_codice(e):
                    mancanti.append(f"{f.name} (listato): " + riga.strip())
    return mancanti


_FINESTRE_CODICE: dict[int, set] = {}


def finestre_codice(e: list[str]) -> set:
    """Finestre di 3 gettoni dell'EPUB (calcolate una volta per sequenza)."""
    if id(e) not in _FINESTRE_CODICE:
        _FINESTRE_CODICE.clear()
        _FINESTRE_CODICE[id(e)] = {tuple(e[i:i + 3]) for i in range(len(e) - 2)}
    return _FINESTRE_CODICE[id(e)]


def alt(tag: str) -> str:
    m = re.search(r"""alt=(?:'([^']*)'|"([^"]*)")""", tag)
    return html.unescape(m.group(1) if m and m.group(1) is not None else (m.group(2) or "") if m else "")


def epubcheck(percorso: Path) -> str | None:
    comando = None
    eseguibile = shutil.which("epubcheck") or ("/usr/bin/epubcheck" if Path("/usr/bin/epubcheck").exists() else None)
    if eseguibile:
        # Alcune distribuzioni installano epubcheck come script, altre come archivio JAR.
        if Path(eseguibile).read_bytes()[:2] == b"PK":
            comando = ["java", "-jar", eseguibile, str(percorso)] if shutil.which("java") else None
        else:
            comando = [eseguibile, str(percorso)]
    if not comando:
        return None
    r = subprocess.run(comando, capture_output=True, text=True)
    m = re.search(r"Messages: (\d+) fatals / (\d+) errors / (\d+) warnings", r.stdout + r.stderr)
    return m.group(0) if m else "EPUBCheck: esito non riconosciuto"


def controlla(nome: str) -> list[str]:
    conf = EDIZIONI[nome]
    problemi = []
    for chiave in ("epub", "pdf"):
        if not conf[chiave].exists():
            return [f"manca {conf[chiave].relative_to(RADICE)}"]

    esito = epubcheck(conf["epub"])
    if esito is None:
        problemi.append("EPUBCheck non disponibile: controllo non eseguito")
    elif not esito.startswith("Messages: 0 fatals / 0 errors / 0 warnings"):
        problemi.append(f"EPUBCheck: {esito}")

    z, opf, pagine = leggi_epub(conf["epub"])
    if not re.search(r"<dc:identifier[^>]*>urn:uuid:[0-9a-f-]{36}</dc:identifier>", opf):
        problemi.append("OPF: identificatore non urn:uuid")
    if "<dc:date>" in opf:
        problemi.append("OPF: dc:date presente (data di compilazione presentata come data di pubblicazione)")
    if f"<dc:language>{conf['lingua']}" not in opf:
        problemi.append(f"OPF: lingua diversa da {conf['lingua']}")
    for voce in ("cover-image", "<dc:rights>", "<dc:title>", "<dc:creator>"):
        if voce not in opf:
            problemi.append(f"OPF: manca {voce}")

    testi = {n: solo_testo(t) for n, t in pagine.items()}
    tutto = "\n".join(testi.values())
    if conf["colophon"] not in " ".join(tutto.split()):
        problemi.append(f"colophon: manca «{conf['colophon']}»")
    if "GPL-3.0-or-later" not in tutto:
        problemi.append("colophon: manca GPL-3.0-or-later")
    m = re.search(r"""<item\b[^>]*href=['"]([^'"]+)['"][^>]*properties=['"]nav['"]""", opf)
    nav = pagine.get("OEBPS/" + m.group(1), "") if m else ""
    capitoli = len(re.findall(r"<li\b", nav))
    if capitoli < 35:
        problemi.append(f"indice navigabile: {capitoli} voci")
    if re.search(r"\?\?", tutto):
        problemi.append(f"rimandi irrisolti: {len(re.findall(r'[?][?]', tutto))} «??»")

    immagini = [m for t in pagine.values() for m in re.finditer(r"<img\b[^>]*>", t, re.S)]
    display = [m.group(0) for t in pagine.values()
               for m in re.finditer(r"<img\b[^>]*class='math-display'[^>]*>|<div class='gather-star'>\s*<img\b[^>]*>", t, re.S)]
    attese = formule_display(conf)
    if len(display) != attese:
        problemi.append(f"formule display: {len(display)} immagini, {attese} nei sorgenti")
    for tag in display:
        a = alt(tag)
        if not a or "\n" in a or "  " in a:
            problemi.append(f"formula display senza testo alternativo curato: {' '.join(a.split())[:80]!r}")
    senza_alt = [t for t in (m.group(0) for m in immagini) if not alt(t).strip()]
    if senza_alt:
        problemi.append(f"{len(senza_alt)} immagini senza testo alternativo")
    figure_attese = len(re.findall(r"\\altfig\{", testo_figure(conf)))
    con_alt = len([m for m in immagini if alt(m.group(0)).strip()]) - len(display)
    if con_alt < figure_attese:
        problemi.append(f"figure: {con_alt} immagini con testo alternativo, {figure_attese} figure nei sorgenti")
    tabelle_src = sum(len(re.findall(r"\\begin\{(?:tabular|tabularx|longtable)\}",
                                     senza_commenti(f.read_text(encoding="utf-8"))))
                      for f in sorgenti(conf, 0) + sorgenti(conf, 1))
    tabelle_epub = sum(t.count("<table") for t in pagine.values())
    if tabelle_epub < tabelle_src:
        problemi.append(f"tabelle: {tabelle_epub} nell'EPUB, {tabelle_src} nei sorgenti")

    # Completezza rispetto al PDF (senza l'indice analitico, che l'EPUB non ha).
    pdf = testo_pdf(conf["pdf"])
    titoli = [m.start() for m in re.finditer(r"(?im)^\f?" + re.escape(conf["indice"]) + r"\s*$", pdf)]
    # Il primo titolo nella seconda meta' del testo: i successivi sono testatine dell'indice.
    titoli = [i for i in titoli if i > len(pdf) // 2]
    if titoli:
        pdf = pdf[:titoli[0]]
    pdf = senza_indice_generale(pdf)
    alt_testo = " ".join(alt(m.group(0)) for m in immagini)
    p_epub = parole(tutto + " " + alt_testo)
    p_pdf = parole(pdf, p_epub)
    # Testo che nell'EPUB e' dentro immagini: figure e sorgenti delle formule display.
    # Nel PDF quel testo puo' uscire senza trattini ("AESGCM") o spezzato lettera per
    # lettera ("PU B K EY"): basta che la parola compaia dentro il loro testo.
    disegno = unicodedata.normalize("NFKC", disegno_figure(conf) + "\n" + sorgente_display(conf)
                                    + "\n" + tabelle_sorgenti(conf)).lower()
    disegno += "\n" + re.sub(r"\\\\|[-\u2010\u2011\s]+", "", disegno)
    voc_disegno = set(sequenza(disegno))
    # Una parola e' "nelle immagini" se compare nel testo disegnato; i frammenti brevi che
    # non sono parole dell'EPUB ("bk", "ersi" da "PUBKEY", "VERSION" spezzati lettera per
    # lettera nel PDF) anche come parte di una parola disegnata.
    in_immagini = lambda w: w in voc_disegno or (len(w) <= 4 and w in disegno and w not in p_epub)
    # pdftotext perde il trattino di alcuni font (grassetto, \\spec): "fixed-size" diventa
    # "fixedsize". Vale anche la forma con il trattino presente nell'EPUB.
    # Nei percorsi e negli URL ("eff-tor-legal-faq") si confrontano le parti unite.
    composte = "\n".join(re.sub(r"[-\u2010\u2011]", "", c).lower()
                         for c in re.findall(r"\w+(?:[-\u2010\u2011]\w+)+", unicodedata.normalize("NFKC", tutto)))
    romani = re.compile(r"^[ivxlc]+$")                       # numeri di pagina iniziali
    # Il titolo dell'indice analitico compare nell'indice generale del PDF; l'EPUB non
    # ha l'indice analitico (i numeri di pagina non hanno senso in un testo fluido).
    titolo_indice = set(parole(conf["indice"]))
    # Due nodi vicini di una figura possono uscire attaccati ("промежуточный" +
    # "шифротекст"): vale se la parola si divide in due parole del testo delle figure.
    voc_immagini = parole(disegno)
    unione = lambda w: any(w[:k] in voc_immagini and w[k:] in voc_immagini for k in range(2, len(w) - 1))
    mancanti = sorted(w for w in p_pdf
                      if w not in p_epub and w not in composte and w not in disegno
                      and not romani.match(w) and w not in titolo_indice and not unione(w))
    if mancanti:
        problemi.append(f"testo: {len(mancanti)} parole del PDF assenti dall'EPUB: {', '.join(mancanti[:15])}")
    # Una parola che compare altrove non rivela un paragrafo mancante: si controlla che
    # ogni frase dei sorgenti (fuori da figure, formule e listati) sia nell'EPUB.
    for frase in frasi_mancanti(conf, tutto):
        problemi.append(f"testo: frase dei sorgenti assente dall'EPUB: «{frase[:120]}»")
    # Virgolette: ogni \\enquote dei capitoli e delle appendici deve dare una virgoletta
    # di apertura e una di chiusura nell'EPUB (tex4ht le scartava nella codifica OT1).
    # Apertura e chiusura si contano separatamente, esterne e annidate, con le
    # convenzioni di ciascuna lingua. ’ non si conta: e' anche l'apostrofo.
    esterne, annidate = conta_enquote(conf)
    corpo = unicodedata.normalize("NFC", tutto)
    (ae, ce), (ai, ci) = conf["virgolette"]
    attese = Counter({ae: esterne, ce: esterne})
    attese[ai] += annidate
    attese[ci] += annidate
    for segno, n in attese.items():
        if segno != "’" and corpo.count(segno) < n:
            problemi.append(f"virgolette {segno}: {corpo.count(segno)} nell'EPUB, "
                            f"almeno {n} attese dalle \\enquote")
    return problemi


def main() -> int:
    scelte = sys.argv[1:] or list(EDIZIONI)
    errore = False
    for nome in scelte:
        problemi = controlla(nome)
        stato = "OK" if not problemi else "PROBLEMI"
        print(f"[{stato}] {nome}: {EDIZIONI[nome]['epub'].relative_to(RADICE)}")
        for p in problemi:
            print(f"    - {p}")
        errore |= bool(problemi)
    return 1 if errore else 0


if __name__ == "__main__":
    sys.exit(main())
