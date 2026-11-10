# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Le fonti assenti non devono produrre un falso successo del controllo."""
import pytest
import verify_spec_references as verifier


def _isola_controlli(monkeypatch, problemi, saltati):
    monkeypatch.setattr(verifier, "problemi", list(problemi))
    monkeypatch.setattr(verifier, "saltati", list(saltati))
    for nome in ("controlla_spec", "controlla_spec_wiki", "controlla_proposte", "controlla_codice"):
        monkeypatch.setattr(verifier, nome, lambda *args: None)


def test_fonti_assenti_non_sono_verifica_superata(monkeypatch, capsys):
    _isola_controlli(monkeypatch, [], ["torspec assente"])
    with pytest.raises(SystemExit) as esito:
        verifier.main()
    assert esito.value.code == 2
    assert "INCOMPLETA" in capsys.readouterr().out


def test_errori_hanno_priorita_su_fonti_mancanti(monkeypatch):
    _isola_controlli(monkeypatch, ["riferimento errato"], ["tor assente"])
    with pytest.raises(SystemExit) as esito:
        verifier.main()
    assert esito.value.code == 1


def test_fonti_complete_senza_errori(monkeypatch):
    _isola_controlli(monkeypatch, [], [])
    with pytest.raises(SystemExit) as esito:
        verifier.main()
    assert esito.value.code == 0
