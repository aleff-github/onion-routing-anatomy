# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
import random

from torlab.directory import analizza_consenso
from torlab.simulazione import Urna, simula
from torlab.test.test_directory import TESTO


def test_urna_quota():
    u = Urna([1.0] * 99, 0.25)
    rng = random.Random(1)
    f = sum(u.ostile(rng) for _ in range(20000)) / 20000
    assert 0.23 < f < 0.27


def test_nessun_avversario():
    r = simula(analizza_consenso(TESTO), 0.0, 0.0, client=20, giorni=5)
    assert r.frazione_entro(5) == 0


def test_guard_persistente_aiuta():
    c = analizza_consenso(TESTO)
    fisso = simula(c, 0.05, 0.05, client=300, giorni=60, guard_persistente=True)
    variabile = simula(c, 0.05, 0.05, client=300, giorni=60, guard_persistente=False)
    assert fisso.frazione_entro(60) < variabile.frazione_entro(60)


import pytest
from torlab import simulazione as _simulation145


def test_sequence145_validate_urn_distribution():
    """Pesi e quote avversarie invalidi vengono rifiutati."""
    for share in (-0.1, 1.1, float("nan"), float("inf"), True):
        with pytest.raises(ValueError):
            _simulation145.Urna([1.0], share)
    for weights in ([float("nan")], [float("inf")], [-1.0], [True], [], [0.0]):
        with pytest.raises(ValueError):
            _simulation145.Urna(weights, 0.25)
    assert _simulation145.Urna([], 1.0).ostile(random.Random(1))
    assert _simulation145.Urna([0.0, 0.0], 1.0).ostile(random.Random(1))
    assert not _simulation145.Urna([1.0], 0.0).ostile(random.Random(1))
    assert isinstance(_simulation145.Urna([1e308, 1e308], 0.25).ostile(random.Random(1)), bool)


def test_sequence145_censored_result_statistics():
    """La mediana rispetta la censura e i campioni pari."""
    R = _simulation145.Risultato
    assert R([1, None]).mediana() == 1
    assert R([1, 3, None, None]).mediana() == 3
    assert R([1, None, None, None]).mediana() is None
    assert R([None, None]).mediana() is None
    assert R([]).mediana() is None
    assert R([2, None]).frazione_entro(0) == 0
    assert R([2, None]).frazione_entro(2) == 0.5
    for day in (-1, 1.2, True):
        with pytest.raises(ValueError):
            R([1, None]).frazione_entro(day)
    with pytest.raises(ValueError):
        R([]).frazione_entro(1)


def test_sequence145_validate_simulation_bounds_and_scale(monkeypatch):
    """Rifiuta dimensioni e quote invalide; verifica scala del consenso e ripetibilità a seme fisso."""
    c = analizza_consenso(TESTO)
    for key in ("client", "giorni", "circuiti", "vita_guard"):
        with pytest.raises(ValueError):
            _simulation145.simula(c, 0.05, 0.05, **{key: 0})
        with pytest.raises(ValueError):
            _simulation145.simula(c, 0.05, 0.05, **{key: True})
    with pytest.raises(ValueError):
        _simulation145.simula(c, 0.05, float("nan"), client=1, giorni=1, circuiti=1)
    c.parametri["bwweightscale"] = 20000
    seen = []
    original = _simulation145.peso
    def record_scale(*args):
        seen.append(args[-1])
        return original(*args)
    monkeypatch.setattr(_simulation145, "peso", record_scale)
    first = _simulation145.simula(c, 0.1, 0.1, client=2, giorni=2, circuiti=1, guard_persistente=False)
    second = _simulation145.simula(c, 0.1, 0.1, client=2, giorni=2, circuiti=1, guard_persistente=False)
    assert first.giorni_compromissione == second.giorni_compromissione
    assert seen and set(seen) == {20000}


def test_sequence145_guard_rotation_one_day(monkeypatch):
    """Il Guard cambia il giorno successivo alla scadenza."""
    c = analizza_consenso(TESTO)
    calls = []
    original = _simulation145.Urna.ostile
    def record_guard(self, rng):
        if self.all_adversarial:
            calls.append(True)
        return original(self, rng)
    monkeypatch.setattr(_simulation145.Urna, "ostile", record_guard)
    result = _simulation145.simula(c, 1.0, 0.0, client=1, giorni=3,
                                     circuiti=1, vita_guard=1, guard_persistente=True)
    assert result.giorni_compromissione == [None]
    assert len(calls) == 3
    assert _simulation145._durata_guard(random.Random(0), 1) == 1
