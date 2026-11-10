# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
#
# Build del libro e dei laboratori. LaTeX gira in Docker (texlive/texlive) se non e'
# installato sull'host. I file pubblicati vanno in book/it/; i file intermedi restano
# accanto ai sorgenti e sono ignorati da git.
#
#   make book-pdf         PDF A4 italiano        -> book/it/anatomia-di-tor_it_A4.pdf
#   make book-epub        EPUB 3 italiano        -> book/it/anatomia-di-tor_it.epub
#   make book-print       PDF 7x10 per la stampa personale (facoltativo)
#   make cover            copertina digitale, immagine social e Open Graph, SVG
#   make book             tutto quanto sopra
#   make book-traduzioni  compila PDF/EPUB/copertine di tutte le bozze linguistiche
#   make book-traduzione LINGUA=en   una sola bozza linguistica (mai in release)
#   make release-package  pacchetto della release in dist/ con SHA256SUMS
#   make release-check    controlli prima di pubblicare la release (non crea nulla)
#   make check            controlli dei sorgenti      make test   test offline
#   make site             sito multilingue in build/site/ (make site-check per i controlli)

IMMAGINE ?= texlive/texlive:latest
TEX_UID ?= $(shell id -u):$(shell id -g)
VERSIONE ?= 1.0.0
LINGUA   ?= it
ifeq ($(shell command -v latexmk 2>/dev/null),)
  # La cache dell'utente del container deve essere scrivibile. Non ridefinire
  # TEXMFCACHE: luaotfload usa i percorsi configurati da TeX Live, con
  # TEXMFVAR come ripiego per l'utente corrente. Un TEXMFCACHE forzato
  # puo' far fallire il caricamento dei font anche con una cache esistente.
  TEX = mkdir -p $(CURDIR)/build/tex-cache/xdg $(CURDIR)/build/tex-cache/texmf-var && docker run --rm \
        -u $(TEX_UID) \
        -e HOME=/w/build/tex-cache \
        -e XDG_CACHE_HOME=/w/build/tex-cache/xdg \
        -e TEXMFVAR=/w/build/tex-cache/texmf-var \
        -v $(CURDIR):/w -w /w/$(1) $(IMMAGINE)
else
  TEX = cd $(1) &&
endif
LATEXMK = latexmk -lualatex -interaction=nonstopmode -halt-on-error -file-line-error
SRC  = source/it
BRANDING = source/branding
OUT  = book/it
NOME = anatomia-di-tor_it
DIST = dist/onion-routing-anatomy-v$(VERSIONE)-$(LINGUA)

.PHONY: capitolo book book-pdf book-epub book-print book-traduzione book-traduzioni cover release-package check fonti composizione epub-check \
        originalita test test-labs verifica-cronologia release-check site site-check site-check-online site-publish verifica-lab verifica-lab-bridge riavvia pulisci

book: cover book-pdf book-epub book-print

# Le traduzioni si compilano per revisione, NON per la release italiana.
# Riutilizza i Makefile localizzati (anche in Docker) e copia i risultati
# in book/<lingua>/ con nomi adeguati alla lingua.
book-traduzioni:
	@set -eu; for l in en es ru zh-Hans; do \
	  $(MAKE) book-traduzione LINGUA=$l; \
	done

book-traduzione:
	@case '$(LINGUA)' in en|es|ru|zh-Hans) ;; *) \
	  echo "LINGUA deve essere en, es, ru o zh-Hans (non it)" >&2; exit 2;; esac
	$(call TEX,source/$(LINGUA)) make cover pdf epub
	python3 scripts/export_draft_book.py $(LINGUA)


book-pdf:
	# main.aux va rimosso: dopo una compilazione parziale (\includeonly) il documento
	# completo verrebbe ricostruito monco.
	rm -f $(SRC)/solo.tex $(SRC)/main.aux
	$(call TEX,$(SRC)) $(LATEXMK) main.tex
	mkdir -p $(OUT) && cp $(SRC)/main.pdf $(OUT)/$(NOME)_A4.pdf
	@echo "PDF A4: $(OUT)/$(NOME)_A4.pdf"

# Formato 7x10 in per chi vuole stampare una copia personale (stessi capitoli).
book-print:
	$(call TEX,$(SRC)) $(LATEXMK) stampa.tex
	mkdir -p $(OUT) && cp $(SRC)/stampa.pdf $(OUT)/$(NOME)_7x10.pdf
	@echo "PDF 7x10: $(OUT)/$(NOME)_7x10.pdf"

# Copertina digitale dell'edizione italiana (solo fronte, 1600x2560, sorgente
# source/it/copertina.tex) e immagini di presentazione del progetto (GitHub 1280x640,
# Open Graph 1200x630, sorgente source/branding/social-preview.tex). L'SVG e' l'export
# vettoriale della copertina, con il testo convertito in tracciati.
cover:
	$(call TEX,$(SRC)) $(LATEXMK) copertina.tex
	$(call TEX,$(SRC)) gs -q -dNOPAUSE -dBATCH -sDEVICE=png16m -r300 \
	  -dTextAlphaBits=4 -dGraphicsAlphaBits=4 -sOutputFile=copertina.png copertina.pdf
	$(call TEX,$(SRC)) gs -q -dNOPAUSE -dBATCH -sDEVICE=jpeg -r300 -dJPEGQ=92 \
	  -dTextAlphaBits=4 -dGraphicsAlphaBits=4 -sOutputFile=copertina.jpg copertina.pdf
	# SVG dal DVI (dvisvgm non legge i PDF con Ghostscript >= 10.01): due passate per
	# le coordinate di «current page» di TikZ, testo convertito in tracciati.
	$(call TEX,$(SRC)) dvilualatex -interaction=nonstopmode -jobname=copertina-svg copertina.tex
	$(call TEX,$(SRC)) dvilualatex -interaction=nonstopmode -jobname=copertina-svg copertina.tex
	$(call TEX,$(SRC)) dvisvgm --no-fonts --output=copertina.svg copertina-svg.dvi
	$(call TEX,$(BRANDING)) $(LATEXMK) -jobname=social-github -usepretex='\def\Larghezza{1280}\def\Altezza{640}' social-preview.tex
	$(call TEX,$(BRANDING)) $(LATEXMK) -jobname=social-opengraph -usepretex='\def\Larghezza{1200}\def\Altezza{630}' social-preview.tex
	$(call TEX,$(BRANDING)) gs -q -dNOPAUSE -dBATCH -sDEVICE=png16m -r72 \
	  -dTextAlphaBits=4 -dGraphicsAlphaBits=4 -sOutputFile=social-github.png social-github.pdf
	$(call TEX,$(BRANDING)) gs -q -dNOPAUSE -dBATCH -sDEVICE=png16m -r72 \
	  -dTextAlphaBits=4 -dGraphicsAlphaBits=4 -sOutputFile=social-opengraph.png social-opengraph.pdf
	mkdir -p $(OUT) website/static/assets assets
	cp $(SRC)/copertina.png $(OUT)/$(NOME)_copertina.png
	cp $(SRC)/copertina.svg $(OUT)/$(NOME)_copertina.svg
	cp $(SRC)/copertina.png website/static/assets/copertina.png
	cp $(BRANDING)/social-opengraph.png website/static/assets/og-image.png
	cp $(BRANDING)/social-github.png assets/social-preview.png
	@echo "Copertine: $(OUT)/, website/static/assets/, assets/social-preview.png"

# EPUB 3 (tex4ebook in modalita' dvilualatex: figure TikZ -> SVG, listati -> <pre>,
# bibliografia via biber, vedi source/it/epub.mk4). daisy-: niente metadati di
# accessibilita' automatici, quelli veri sono in source/it/epub.tex. La copertina
# interna e' source/it/copertina.jpg, generata da make cover.
book-epub:
	test -f $(SRC)/copertina.jpg || $(MAKE) cover
	rm -f $(SRC)/solo.tex
	$(call TEX,$(SRC)) tex4ebook -l -f epub3 -e epub.mk4 epub.tex "svg,daisy-"
	# tex4ht scrive negli .aux dei capitoli (condivisi con la stampa) macro come
	# \rEfLiNK che farebbero fallire una successiva compilazione PDF: li rimuoviamo.
	rm -f $(SRC)/epub.aux $(SRC)/capitoli/*.aux $(SRC)/appendici/*.aux
	mkdir -p $(OUT) && cp $(SRC)/epub.epub $(OUT)/$(NOME).epub
	@echo "EPUB: $(OUT)/$(NOME).epub"

# Pacchetto della release: i file di book/it, le note e SHA256SUMS, poi uno ZIP.
release-package:
	rm -rf $(DIST) && mkdir -p $(DIST)
	cp $(OUT)/$(NOME)_A4.pdf $(OUT)/$(NOME).epub $(OUT)/$(NOME)_copertina.png $(DIST)/
	test ! -f $(OUT)/$(NOME)_7x10.pdf || cp $(OUT)/$(NOME)_7x10.pdf $(DIST)/
	cp docs/releases/v$(VERSIONE)-$(LINGUA).md $(DIST)/RELEASE-NOTES.md
	cp LICENSE NOTICE.md $(DIST)/
	cd $(DIST) && sha256sum *.pdf *.epub *.png RELEASE-NOTES.md LICENSE NOTICE.md > SHA256SUMS
	cd dist && rm -f $(notdir $(DIST)).zip && zip -q -r -X $(notdir $(DIST)).zip $(notdir $(DIST))
	cd dist && sha256sum $(notdir $(DIST)).zip > $(notdir $(DIST)).zip.sha256
	@cat $(DIST)/SHA256SUMS
	@echo "Pacchetto: dist/$(notdir $(DIST)).zip"

# Coerenza di versione, note, impronte, pacchetto e tag prima di pubblicare una release.
release-check:
	python3 scripts/check_release.py

check:
	python3 scripts/check_sources.py
	python3 scripts/generate_readme_it.py --check
	python3 scripts/check_markdown_links.py
	python3 scripts/check_public_copy.py
	python3 scripts/build_site.py build
	python3 scripts/build_site.py check
	python3 scripts/check_wording.py
	python3 scripts/check_cross_references.py
	python3 scripts/verify_listings.py

# Dati da non pubblicare (email personali, riferimenti alle sessioni di lavoro, chiavi,
# catture) in ogni blob e messaggio della cronologia (scripts/check_history.py).
verifica-cronologia:
	python3 scripts/check_history.py

# Sito statico multilingue (website/ -> build/site/). site-publish prepara il branch
# gh-pages senza inviarlo; PUSH=1 lo invia (docs/maintainers/github-pages.md). site-check-online
# controlla il sito gia' pubblicato all'indirizzo di website/site.toml.
site:
	python3 scripts/build_site.py build

site-check: site
	python3 scripts/build_site.py check

site-check-online:
	python3 scripts/build_site.py check-online

site-publish:
	sh scripts/publish_site.sh $(if $(PUSH),--push)

# Riferimenti a torspec, proposte e codice di tor (richiede i sorgenti in fonti/).
fonti:
	python3 scripts/verify_spec_references.py

# Il codice arriva intatto sulla pagina (richiede source/<lingua>/main.pdf: make book-pdf,
# make -C source/<lingua> pdf). LINGUE="it en es ru zh-Hans" controlla anche le traduzioni.
LINGUE ?= it
composizione:
	python3 scripts/check_pdf_code.py $(LINGUE)

# EPUB: EPUBCheck, metadati, completezza del testo rispetto al PDF e ai sorgenti, formule,
# figure, virgolette (richiede gli EPUB e i PDF delle edizioni in $(LINGUE)).
epub-check:
	python3 scripts/check_epub.py $(LINGUE)

# Sequenze copiate dalle fonti (richiede un corpus in fonti/).
originalita:
	python3 scripts/check_originality.py

# Test offline degli strumenti e del codice dei laboratori: niente Docker, Tor o rete.
test: test-labs
	python3 -m pytest -q scripts/tests

test-labs:
	$(MAKE) -C labs/it test

# Riesegue dal vivo i laboratori italiani (richiede la rete: make -C labs/it avvia).
verifica-lab:
	python3 scripts/verify_labs.py

# Laboratorio 10: scambio protetto libro -> libro-bridge -> libro (scripts/swap_bridge_network.py):
# 0 = controlli superati, 1 = controlli falliti, 2 = non eseguito, 3 = ripristino da
# completare a mano (docs/it/procedura-laboratori-dal-vivo.md, §8).
verifica-lab-bridge:
	python3 scripts/swap_bridge_network.py

riavvia:
	-rm -f labs/it/laboratorio/net/nodes/*/pid
	docker exec torlibro-rete chutney start
	docker exec -e CHUTNEY_LAUNCH_PHASE=2 torlibro-rete chutney start
	docker exec torlibro-rete chutney wait_for_bootstrap

pulisci:
	$(call TEX,$(SRC)) latexmk -C main.tex stampa.tex

# Un solo capitolo dell'edizione A4, per lavorarci. Esempio: make capitolo N=08
capitolo:
	@f=$$(cd $(SRC) && ls capitoli/$(N)-*.tex appendici/$(N)-*.tex 2>/dev/null | head -1); \
	test -n "$$f" || { echo "Capitolo $(N) non trovato"; exit 1; }; \
	echo "\\includeonly{$${f%.tex}}" > $(SRC)/solo.tex
	$(call TEX,$(SRC)) $(LATEXMK) main.tex; rm -f $(SRC)/solo.tex
