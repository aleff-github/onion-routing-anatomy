# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Ambiente dei laboratori — Italiano
.PHONY: test data immagine avvia verifica stato ferma pulisci

test:
	PYTHONPATH=codice python3 -m pytest -q codice/torlab/test

# Scarica, solo su richiesta, il consenso pubblico storico dei Laboratori 7, 15 e 19
# in dati/collector/. Controlla l'intestazione, non le firme (vedi dati/README.md).
data:
	sh fetch-public-data.sh

immagine:
	$(MAKE) -C laboratorio immagine

avvia:
	$(MAKE) -C laboratorio avvia

verifica:
	$(MAKE) test
	$(MAKE) -C laboratorio verifica

stato:
	$(MAKE) -C laboratorio stato

ferma:
	$(MAKE) -C laboratorio ferma

pulisci:
	$(MAKE) -C laboratorio pulisci
