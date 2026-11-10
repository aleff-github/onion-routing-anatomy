# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Test offline dei verificatori: nessun Docker, Tor, Chutney o collegamento esterno.

Due protezioni valgono per ogni test:
- una connessione verso un indirizzo diverso da 127.0.0.1/::1 fa fallire il test;
- l'avvio di docker, tor, chutney, tcpdump, tshark o curl da Python fa fallire il test.
"""
from __future__ import annotations

import ipaddress
import socket
import subprocess
import sys
from pathlib import Path

import pytest

STRUMENTI = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(STRUMENTI))

VIETATI = {"docker", "tor", "chutney", "tcpdump", "tshark", "curl"}


def _solo_loopback(indirizzo) -> None:
    if isinstance(indirizzo, tuple):
        try:
            if ipaddress.ip_address(indirizzo[0]).is_loopback:
                return
        except ValueError:
            pass
        raise AssertionError(f"test offline: connessione verso {indirizzo!r} vietata")


@pytest.fixture(autouse=True)
def isolamento(monkeypatch):
    originale_connect = socket.socket.connect
    originale_connect_ex = socket.socket.connect_ex

    def connect(self, indirizzo):
        _solo_loopback(indirizzo)
        return originale_connect(self, indirizzo)

    def connect_ex(self, indirizzo):
        _solo_loopback(indirizzo)
        return originale_connect_ex(self, indirizzo)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)

    originale_popen = subprocess.Popen

    class PopenControllato(originale_popen):
        def __init__(self, args, *a, **k):
            primo = args if isinstance(args, str) else args[0]
            if Path(str(primo).split()[0]).name in VIETATI:
                raise AssertionError(f"test offline: avvio di {primo!r} vietato")
            super().__init__(args, *a, **k)

    monkeypatch.setattr(subprocess, "Popen", PopenControllato)
