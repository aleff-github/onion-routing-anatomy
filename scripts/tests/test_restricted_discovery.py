# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Lab 13: la pulizia preliminare non deve alterare un torrc senza residui (prima
validazione dal vivo, 28/10/2026: il ripristino perdeva la riga vuota finale)."""
from __future__ import annotations

import sys
import stat
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "labs" / "it" / "laboratorio"))
import scoperta_ristretta as sr  # noqa: E402


def _nodi(tmp_path, monkeypatch, torrc_servizio, torrc_client):
    servizio, client = tmp_path / "009h", tmp_path / "008c"
    servizio.mkdir(), client.mkdir()
    (servizio / "torrc").write_text(torrc_servizio)
    (client / "torrc").write_text(torrc_client)
    monkeypatch.setattr(sr, "SERVIZIO", servizio)
    monkeypatch.setattr(sr, "CLIENT", client)
    monkeypatch.setattr(sr, "HS", servizio / "hs_ristretto")
    monkeypatch.setattr(sr, "AUTH", client / "onion_auth")
    return servizio / "torrc", client / "torrc"


def test_torrc_senza_residui_resta_identico_byte_per_byte(tmp_path, monkeypatch):
    originali = ("DataDirectory /lab/net/nodes.1/009h\nHiddenServicePort 80 127.0.0.1:5858\n\n",
                 "DataDirectory /lab/net/nodes.1/008c\nSocksPort 127.0.0.1:9008\n\n")
    s, c = _nodi(tmp_path, monkeypatch, *originali)
    sr.ripulisci()
    assert (s.read_text(), c.read_text()) == originali


def test_residui_di_una_esecuzione_interrotta_vengono_tolti(tmp_path, monkeypatch):
    s, c = _nodi(tmp_path, monkeypatch,
                 "DataDirectory /x\n\nHiddenServiceDir /x/hs_ristretto\nHiddenServicePort 80 127.0.0.1:8080\n",
                 "DataDirectory /y\n\nClientOnionAuthDir /y/onion_auth\n")
    sr.ripulisci()
    assert "hs_ristretto" not in s.read_text() and "8080" not in s.read_text()
    assert "ClientOnionAuthDir" not in c.read_text()

def test_ripulisci_non_cancella_chiavi_sconosciute(tmp_path, monkeypatch):
    sorgente = "DataDirectory /lab/nodes/009h\n"
    client = "DataDirectory /lab/nodes/008c\n"
    torrc_s, torrc_c = _nodi(tmp_path, monkeypatch, sorgente, client)
    sr.HS.mkdir()
    chiave = sr.HS / "hs_ed25519_secret_key"
    chiave.write_text("chiave-da-non-cancellare")
    with pytest.raises(RuntimeError, match="preesistente"):
        sr.ripulisci()
    assert chiave.read_text() == "chiave-da-non-cancellare"
    assert torrc_s.read_text() == sorgente and torrc_c.read_text() == client


def test_ripulisci_rimuove_solo_directory_marcate(tmp_path, monkeypatch):
    torrc_s, torrc_c = _nodi(
        tmp_path, monkeypatch,
        "DataDirectory /x\nHiddenServiceDir /x/hs_ristretto\nHiddenServicePort 80 127.0.0.1:8080\n",
        "DataDirectory /y\nClientOnionAuthDir /y/onion_auth\n",
    )
    for folder in (sr.HS, sr.AUTH):
        folder.mkdir()
        (folder / sr.MARCATORE).touch()
        (folder / "prova.txt").write_text("temporaneo")
    sr.ripulisci()
    assert not sr.HS.exists() and not sr.AUTH.exists()
    assert "hs_ristretto" not in torrc_s.read_text()
    assert "ClientOnionAuthDir" not in torrc_c.read_text()


def test_chiave_privata_scritta_solo_con_permessi_0600(tmp_path):
    file = tmp_path / "alice.auth_private"
    sr._scrivi_segreto_privato(file, "prova-di-laboratorio")
    assert stat.S_IMODE(file.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        sr._scrivi_segreto_privato(file, "non-sovrascrivere")
    assert file.read_text() == "prova-di-laboratorio"
