# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
import random

from torlab.directory import parse_consensus
from torlab.simulation import WeightedUrn, simulate
from torlab.test.test_directory import TEXT


def test_urn_share():
    u = WeightedUrn([1.0] * 99, 0.25)
    rng = random.Random(1)
    f = sum(u.adversarial(rng) for _ in range(20000)) / 20000
    assert 0.23 < f < 0.27


def test_no_adversary():
    r = simulate(parse_consensus(TEXT), 0.0, 0.0, client=20, days=5)
    assert r.fraction_by(5) == 0


def test_persistent_guard_helps():
    c = parse_consensus(TEXT)
    fixed = simulate(c, 0.05, 0.05, client=300, days=60, persistent_guard=True)
    variable = simulate(c, 0.05, 0.05, client=300, days=60, persistent_guard=False)
    assert fixed.fraction_by(60) < variable.fraction_by(60)


import pytest
from torlab import simulation as _simulation145


def test_sequence145_validate_urn_distribution():
    """Недопустимые веса и доли противника отклоняются."""
    for share in (-0.1, 1.1, float("nan"), float("inf"), True):
        with pytest.raises(ValueError):
            _simulation145.WeightedUrn([1.0], share)
    for weights in ([float("nan")], [float("inf")], [-1.0], [True], [], [0.0]):
        with pytest.raises(ValueError):
            _simulation145.WeightedUrn(weights, 0.25)
    assert _simulation145.WeightedUrn([], 1.0).adversarial(random.Random(1))
    assert _simulation145.WeightedUrn([0.0, 0.0], 1.0).adversarial(random.Random(1))
    assert not _simulation145.WeightedUrn([1.0], 0.0).adversarial(random.Random(1))
    assert isinstance(_simulation145.WeightedUrn([1e308, 1e308], 0.25).adversarial(random.Random(1)), bool)


def test_sequence145_censored_result_statistics():
    """Медиана учитывает цензуру и чётное число клиентов."""
    R = _simulation145.Result
    assert R([1, None]).median() == 1
    assert R([1, 3, None, None]).median() == 3
    assert R([1, None, None, None]).median() is None
    assert R([None, None]).median() is None
    assert R([]).median() is None
    assert R([2, None]).fraction_by(0) == 0
    assert R([2, None]).fraction_by(2) == 0.5
    for day in (-1, 1.2, True):
        with pytest.raises(ValueError):
            R([1, None]).fraction_by(day)
    with pytest.raises(ValueError):
        R([]).fraction_by(1)


def test_sequence145_validate_simulation_bounds_and_scale(monkeypatch):
    """Отклоняются недопустимые размеры и доли; проверяются масштаб весов и воспроизводимость с фиксированным начальным значением."""
    c = parse_consensus(TEXT)
    for key in ("client", "days", "circuits", "guard_lifetime"):
        with pytest.raises(ValueError):
            _simulation145.simulate(c, 0.05, 0.05, **{key: 0})
        with pytest.raises(ValueError):
            _simulation145.simulate(c, 0.05, 0.05, **{key: True})
    with pytest.raises(ValueError):
        _simulation145.simulate(c, 0.05, float("nan"), client=1, days=1, circuits=1)
    c.parameters["bwweightscale"] = 20000
    seen = []
    original = _simulation145.weight
    def record_scale(*args):
        seen.append(args[-1])
        return original(*args)
    monkeypatch.setattr(_simulation145, "weight", record_scale)
    first = _simulation145.simulate(c, 0.1, 0.1, client=2, days=2, circuits=1, persistent_guard=False)
    second = _simulation145.simulate(c, 0.1, 0.1, client=2, days=2, circuits=1, persistent_guard=False)
    assert first.days_to_compromise == second.days_to_compromise
    assert seen and set(seen) == {20000}


def test_sequence145_guard_rotation_one_day(monkeypatch):
    """Замена Guard происходит в первый день после истечения срока."""
    c = parse_consensus(TEXT)
    calls = []
    original = _simulation145.WeightedUrn.adversarial
    def record_guard(self, rng):
        if self.all_adversarial:
            calls.append(True)
        return original(self, rng)
    monkeypatch.setattr(_simulation145.WeightedUrn, "adversarial", record_guard)
    result = _simulation145.simulate(c, 1.0, 0.0, client=1, days=3,
                                     circuits=1, guard_lifetime=1, persistent_guard=True)
    assert result.days_to_compromise == [None]
    assert len(calls) == 3
    assert _simulation145._guard_lifetime(random.Random(0), 1) == 1
