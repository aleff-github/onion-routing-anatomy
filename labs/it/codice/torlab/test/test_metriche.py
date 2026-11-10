# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
import pytest
from torlab.directory import analizza_consenso
from torlab.metriche import riassunto, stima_utenti, togli_arrotondamento
from torlab.test.test_directory import TESTO


def test_stima_utenti():
    assert stima_utenti(1_000_000, 0.5) == 200_000
    assert stima_utenti(1_000_000, 0.05) is None
    assert stima_utenti(1_000_000, 1.2) is None


def test_arrotondamento():
    assert togli_arrotondamento(16) == 12
    assert togli_arrotondamento(8) == 4
    assert togli_arrotondamento(4) is None


def test_riassunto():
    r = riassunto(analizza_consenso(TESTO))
    assert r["relay"] == len(analizza_consenso(TESTO).relay)
    assert 0 <= r["quota_banda_exit"] <= 1


def test_riassunto_deterministico():
    """L'ordine dei flag a parità di conteggio non deve dipendere dall'esecuzione."""
    c = analizza_consenso(TESTO)
    assert list(riassunto(c)["flag"].items()) == list(riassunto(analizza_consenso(TESTO))["flag"].items())
    coppie = list(riassunto(c)["flag"].items())
    assert coppie == sorted(coppie, key=lambda x: (-x[1], x[0]))


def test_banda_zero_senza_quota():
    """La quota non è definita quando il consenso non ha banda."""
    c = analizza_consenso(TESTO)
    c.relay.clear()
    empty = riassunto(c)
    assert empty["relay"] == 0
    assert empty["banda_totale"] == 0
    assert empty["quota_banda_exit"] is None
    assert empty["quota_banda_guard"] is None

    c = analizza_consenso(TESTO)
    for relay in c.relay:
        relay.banda = 0
    zero = riassunto(c)
    assert zero["banda_totale"] == 0
    assert zero["quota_banda_exit"] is None
    assert zero["quota_banda_guard"] is None


def test_stima_valori_invalidi():
    """I contatori negativi e le frazioni non finite non producono stime valide."""
    for requests in (-1, True, 1.5):
        with pytest.raises(ValueError):
            stima_utenti(requests, 0.5)
    assert stima_utenti(0, 0.1) == 0
    assert stima_utenti(0, 1.1) == 0
    assert stima_utenti(1000, float("nan")) is None
    assert stima_utenti(1000, float("inf")) is None
    assert stima_utenti(1000, -float("inf")) is None
    assert stima_utenti(1000, True) is None


def test_arrotondamento_valori_invalidi():
    """Il passo di arrotondamento deve essere intero, positivo e pari."""
    for step in (0, -2, 3, True):
        with pytest.raises(ValueError):
            togli_arrotondamento(16, step)
    for value in (-1, True, 1.5):
        with pytest.raises(ValueError):
            togli_arrotondamento(value)
    assert togli_arrotondamento(16, 4) == 14
