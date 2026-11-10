# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
import copy
import random

import pytest

from torlab.directory import parse_consensus
from torlab.path_selection import Selector, _relay_type, weight, network16
from torlab.test.test_directory import TEXT


def test_path_respects_constraints():
    c = parse_consensus(TEXT)
    sel, rng = Selector(c), random.Random(0)
    for _ in range(200):
        g, m, e = sel.path(rng, distinct_networks=False)   # en el laboratorio todos los nodos usan 127.0.0.1
        assert len({g.id_rsa, m.id_rsa, e.id_rsa}) == 3
        assert "Guard" in g.flag and "Exit" in e.flag


def test_same_network_rejection():
    c = parse_consensus(TEXT)
    sel = Selector(c)
    assert c.relay and {network16(r) for r in c.relay} == {"127.0"}
    assert all(sel.candidates[pos] for pos in ("guard", "middle", "exit"))
    with pytest.raises(LookupError):
        sel.path(random.Random(0), distinct_networks=True)


def test_weights():
    c = parse_consensus(TEXT)
    e = next(r for r in c.relay if "Exit" in r.flag)
    assert _relay_type(e) == "d"             # las salidas de laboratorio también poseen el indicador Guard
    assert weight(e, "exit", {"Wed": 5000}) == e.bandwidth / 2


from torlab import path_selection as _paths142


def test_sequence142_consensus_scaling():
    """Comprobar la escala del consenso y el caso sin candidatos."""
    c = parse_consensus(TEXT)
    relay = next(r for r in c.relay if "Exit" in r.flag)
    c.parameters["bwweightscale"] = 20000
    assert _paths142.weight(relay, "exit", {"Wed": 10000}, 20000) == relay.bandwidth / 2
    assert _paths142.Selector(c).scale == 20000
    c.relay.clear()
    assert _paths142.probabilities(c, "guard") == {}
    with pytest.raises(LookupError):
        _paths142.Selector(c).choose("guard", [], random.Random(0))


def test_sequence142_identity_and_feasible_sampling():
    """Los repetidores se distinguen por su identidad, no por el objeto Python."""
    c = parse_consensus(TEXT)
    sel = _paths142.Selector(c)
    candidates = sel.candidates["middle"]
    assert candidates
    target = candidates[0]
    excluded = [copy.copy(relay) for relay in candidates[1:]]
    picked = sel.choose("middle", excluded, random.Random(0),
                             distinct_networks=False,
                             attempts=1)
    assert picked.id_rsa == target.id_rsa
    with pytest.raises(LookupError):
        sel.choose("middle", [copy.copy(r) for r in candidates], random.Random(0),
                         distinct_networks=False)


def test_sequence142_bad_weights_networks_and_risk():
    """Rechazar pesos, redes y probabilidades de riesgo inválidos."""
    c = parse_consensus(TEXT)
    relay = copy.copy(c.relay[0])
    with pytest.raises(ValueError):
        _paths142.weight(relay, "unknown", {})
    with pytest.raises(ValueError):
        _paths142.eligible(relay, "unknown")
    with pytest.raises(ValueError):
        _paths142.weight(relay, "middle", {"Wm" + _paths142._relay_type(relay): -1})
    with pytest.raises(ValueError):
        _paths142.weight(relay, "middle", {}, 0)
    relay.ip = "999.1.1.1"
    with pytest.raises(ValueError):
        _paths142.network16(relay)
    with pytest.raises(ValueError):
        _paths142.top_share({}, -1)
    with pytest.raises(ValueError):
        _paths142.Adversary(float("nan"), 0.2)
    with pytest.raises(ValueError):
        _paths142.Adversary(1.1, 0.2)
    assert _paths142.Adversary(0.2, 0.3).compromised_circuits(0, False) == 0
    with pytest.raises(ValueError):
        _paths142.Adversary(0.2, 0.3).compromised_circuits(-1, False)


def test_sequence142_fixed_guard_validation():
    """El Guard fijado debe pertenecer a los candidatos del consenso."""
    c = parse_consensus(TEXT)
    sel = _paths142.Selector(c)
    guard = copy.copy(sel.candidates["guard"][0])
    guard.id_rsa = b"invalid-identity!!"
    with pytest.raises(LookupError):
        sel.path(random.Random(0), guard=guard, distinct_networks=False)
    valid = sel.candidates["guard"][0]
    g, m, e = sel.path(random.Random(0), guard=valid,
                            distinct_networks=False)
    assert g.id_rsa == valid.id_rsa
    assert len({g.id_rsa, m.id_rsa, e.id_rsa}) == 3


def test_sequence142_badexit_weight_category():
    """BadExit no puede ser salida, pero conserva la categoría Exit para el peso."""
    c = parse_consensus(TEXT)
    relay = copy.copy(next(r for r in c.relay if "Guard" in r.flag and "Exit" in r.flag))
    relay.flag = set(relay.flag) | {"BadExit"}
    assert _paths142._relay_type(relay) == "d"
    assert not _paths142.eligible(relay, "exit")
