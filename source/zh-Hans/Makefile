# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
#
# Build della traduzione (stato in docs/translations/zh-Hans.md): richiede LaTeX locale
# (LuaLaTeX, latexmk, biber, tex4ebook). La traduzione e' in revisione: i file
# generati non vanno pubblicati come download prima dell'approvazione.
LATEXMK = latexmk -lualatex -interaction=nonstopmode -halt-on-error -file-line-error
.PHONY: pdf epub cover check clean

pdf:
	$(LATEXMK) main.tex

epub:
	test -f epub-cover.jpg || $(MAKE) cover
	tex4ebook -l -f epub3 -e epub.mk4 epub.tex "svg,daisy-"
	rm -f epub.aux 章节/*.aux 附录/*.aux

cover:
	$(LATEXMK) 封面.tex
	gs -q -dNOPAUSE -dBATCH -sDEVICE=png16m -r300 -dTextAlphaBits=4 -dGraphicsAlphaBits=4 \
	  -sOutputFile=封面.png 封面.pdf
	gs -q -dNOPAUSE -dBATCH -sDEVICE=jpeg -r300 -dJPEGQ=92 -dTextAlphaBits=4 -dGraphicsAlphaBits=4 \
	  -sOutputFile=epub-cover.jpg 封面.pdf

# Controlli strutturali: stesso numero di capitoli, appendici e figure dell'edizione
# italiana (i nomi dei file sono nella lingua di ciascuna edizione), testo alternativo
# in ogni figura. Non verifica la traduzione.
check:
	@set -eu; \
	confronta() { test "$$1" -eq "$$2" || { echo "$$3: $$1 in questa edizione, $$2 in quella italiana" >&2; exit 1; }; }; \
	confronta $$(ls 章节/*.tex | wc -l) $$(ls ../it/capitoli/*.tex | grep -vc 00-nota-edizioni-tradotte) capitoli; \
	confronta $$(ls 附录/*.tex | wc -l) $$(ls ../it/appendici/*.tex | wc -l) appendici; \
	confronta $$(ls 图/*.tex | wc -l) $$(ls ../it/figure/*.tex | wc -l) figure
	@set -eu; for fig in 图/*.tex; do \
	  grep -Fq '\altfig{' "$$fig" || { echo "manca il testo alternativo: $$fig" >&2; exit 1; }; \
	done
	@echo "controlli strutturali superati"

clean:
	latexmk -C main.tex 封面.tex
