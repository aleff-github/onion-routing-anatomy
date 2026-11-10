# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Il controllo di originalità non deve risultare superato senza fonti da confrontare."""
import pytest

from check_originality import costruisci_indice


def test_corpus_mancante(tmp_path):
    with pytest.raises(ValueError, match="corpus non trovato"):
        costruisci_indice([str(tmp_path / "inesistente")], 8)


def test_corpus_vuoto(tmp_path):
    with pytest.raises(ValueError, match="nessun file di riferimento"):
        costruisci_indice([str(tmp_path)], 8)


def test_corpus_troppo_corto(tmp_path):
    (tmp_path / "sorgente.md").write_text("solo due parole", encoding="utf-8")
    with pytest.raises(ValueError, match="nessun file di riferimento"):
        costruisci_indice([str(tmp_path)], 8)


def test_corpus_valido(tmp_path):
    documento = tmp_path / "specifica.md"
    documento.write_text("uno due tre quattro cinque sei sette otto nove", encoding="utf-8")
    indice = costruisci_indice([str(tmp_path)], 8)
    assert indice["uno due tre quattro cinque sei sette otto"] == str(documento)
    assert len(indice) == 2


def test_file_singolo(tmp_path):
    documento = tmp_path / "fonte.txt"
    documento.write_text("uno due tre quattro cinque sei sette otto", encoding="utf-8")
    assert len(costruisci_indice([str(documento)], 8)) == 1


def test_n_non_valido(tmp_path):
    with pytest.raises(ValueError, match="almeno 2"):
        costruisci_indice([str(tmp_path)], 1)


def test_un_corpus_mancante_fa_fallire_tutti(tmp_path):
    documento = tmp_path / "fonte.txt"
    documento.write_text("uno due tre quattro cinque sei sette otto", encoding="utf-8")
    with pytest.raises(ValueError, match="corpus non trovato"):
        costruisci_indice([str(documento), str(tmp_path / "mancante")], 8)
