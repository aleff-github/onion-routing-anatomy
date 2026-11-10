# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
import copy
import random

import pytest

from torlab.directory import analizza_consenso
from torlab.percorso import Selettore, _tipo, peso, rete16
from torlab.test.test_directory import TESTO


def test_percorso_rispetta_i_vincoli():
    c = analizza_consenso(TESTO)
    sel, rng = Selettore(c), random.Random(0)
    for _ in range(200):
        g, m, e = sel.percorso(rng, distinte_reti=False)   # nel laboratorio tutto è 127.0.0.1
        assert len({g.id_rsa, m.id_rsa, e.id_rsa}) == 3
        assert "Guard" in g.flag and "Exit" in e.flag


def test_rifiuto_stessa_rete():
    c = analizza_consenso(TESTO)
    sel = Selettore(c)
    assert c.relay and {rete16(r) for r in c.relay} == {"127.0"}
    assert all(sel.candidati[pos] for pos in ("guard", "middle", "exit"))
    with pytest.raises(LookupError):
        sel.percorso(random.Random(0), distinte_reti=True)


def test_pesi():
    c = analizza_consenso(TESTO)
    e = next(r for r in c.relay if "Exit" in r.flag)
    assert _tipo(e) == "d"             # nel laboratorio gli exit hanno anche Guard
    assert peso(e, "exit", {"Wed": 5000}) == e.banda / 2


from torlab import percorso as _paths142


def test_sequence142_consensus_scaling():
    """Verifica la scala del consenso e il caso senza candidati."""
    c = analizza_consenso(TESTO)
    relay = next(r for r in c.relay if "Exit" in r.flag)
    c.parametri["bwweightscale"] = 20000
    assert _paths142.peso(relay, "exit", {"Wed": 10000}, 20000) == relay.banda / 2
    assert _paths142.Selettore(c).scale == 20000
    c.relay.clear()
    assert _paths142.probabilita(c, "guard") == {}
    with pytest.raises(LookupError):
        _paths142.Selettore(c).scegli("guard", [], random.Random(0))


def test_sequence142_identity_and_feasible_sampling():
    """La distinzione dei relay usa l'identità, non l'oggetto Python."""
    c = analizza_consenso(TESTO)
    sel = _paths142.Selettore(c)
    candidates = sel.candidati["middle"]
    assert candidates
    target = candidates[0]
    excluded = [copy.copy(relay) for relay in candidates[1:]]
    picked = sel.scegli("middle", excluded, random.Random(0),
                             distinte_reti=False,
                             tentativi=1)
    assert picked.id_rsa == target.id_rsa
    with pytest.raises(LookupError):
        sel.scegli("middle", [copy.copy(r) for r in candidates], random.Random(0),
                         distinte_reti=False)


def test_sequence142_bad_weights_networks_and_risk():
    """Pesi, reti e probabilità di rischio errati vengono rifiutati."""
    c = analizza_consenso(TESTO)
    relay = copy.copy(c.relay[0])
    with pytest.raises(ValueError):
        _paths142.peso(relay, "unknown", {})
    with pytest.raises(ValueError):
        _paths142.idoneo(relay, "unknown")
    with pytest.raises(ValueError):
        _paths142.peso(relay, "middle", {"Wm" + _paths142._tipo(relay): -1})
    with pytest.raises(ValueError):
        _paths142.peso(relay, "middle", {}, 0)
    relay.ip = "999.1.1.1"
    with pytest.raises(ValueError):
        _paths142.rete16(relay)
    with pytest.raises(ValueError):
        _paths142.quota_primi({}, -1)
    with pytest.raises(ValueError):
        _paths142.Avversario(float("nan"), 0.2)
    with pytest.raises(ValueError):
        _paths142.Avversario(1.1, 0.2)
    assert _paths142.Avversario(0.2, 0.3).circuiti_compromessi(0, False) == 0
    with pytest.raises(ValueError):
        _paths142.Avversario(0.2, 0.3).circuiti_compromessi(-1, False)


def test_sequence142_fixed_guard_validation():
    """Il Guard fissato deve appartenere ai candidati validi del consenso."""
    c = analizza_consenso(TESTO)
    sel = _paths142.Selettore(c)
    guard = copy.copy(sel.candidati["guard"][0])
    guard.id_rsa = b"invalid-identity!!"
    with pytest.raises(LookupError):
        sel.percorso(random.Random(0), guard=guard, distinte_reti=False)
    valid = sel.candidati["guard"][0]
    g, m, e = sel.percorso(random.Random(0), guard=valid,
                            distinte_reti=False)
    assert g.id_rsa == valid.id_rsa
    assert len({g.id_rsa, m.id_rsa, e.id_rsa}) == 3


def test_sequence142_badexit_weight_category():
    """Un BadExit non può essere uscita ed è pesato come non-exit, come in tor (cap. 13)."""
    c = analizza_consenso(TESTO)
    relay = copy.copy(next(r for r in c.relay if "Guard" in r.flag and "Exit" in r.flag))
    relay.flag = set(relay.flag) | {"BadExit"}
    assert _paths142._tipo(relay) == "g"
    assert not _paths142.idoneo(relay, "exit")

def test_peso_numerico_non_rende_relay_idoneo_a_guard_o_exit():
    """La tabella del cap. 13 separa peso in consenso e vincoli della posizione."""
    from torlab.percorso import idoneo

    c = analizza_consenso(TESTO)
    relay = copy.copy(c.relay[0])
    relay.flag = {"Running", "Valid", "Fast"}
    relay.banda = 2000

    # Valori presenti nella famiglia dei coefficienti di consenso:
    # il peso puo' essere positivo anche per una combinazione NON idonea.
    assert peso(relay, "guard", {"Wgm": 6195}) > 0
    assert peso(relay, "exit", {"Wem": 10000}) > 0
    assert not idoneo(relay, "guard")   # assenza flag Guard
    assert not idoneo(relay, "exit")    # assenza flag Exit

    relay.flag.add("Guard")
    assert idoneo(relay, "guard")
    assert not idoneo(relay, "exit")
