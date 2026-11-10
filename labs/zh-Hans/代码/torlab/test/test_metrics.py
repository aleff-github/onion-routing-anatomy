# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
import pytest
from torlab.directory import parse_consensus
from torlab.metrics import summary, estimate_users, remove_rounding
from torlab.test.test_directory import TEXT


def test_user_estimate():
    assert estimate_users(1_000_000, 0.5) == 200_000
    assert estimate_users(1_000_000, 0.05) is None
    assert estimate_users(1_000_000, 1.2) is None


def test_rounding():
    assert remove_rounding(16) == 12
    assert remove_rounding(8) == 4
    assert remove_rounding(4) is None


def test_summary():
    r = summary(parse_consensus(TEXT))
    assert r["relay"] == len(parse_consensus(TEXT).relay)
    assert 0 <= r["exit_bandwidth_share"] <= 1


def test_summary_is_deterministic():
    """计数相同时，标志排序不应随运行次数改变。"""
    c = parse_consensus(TEXT)
    assert list(summary(c)["flag"].items()) == list(summary(parse_consensus(TEXT))["flag"].items())
    pairs = list(summary(c)["flag"].items())
    assert pairs == sorted(pairs, key=lambda x: (-x[1], x[0]))


def test_zero_bandwidth_is_undefined():
    """共识为空或总带宽为零时，占比不应被定义。"""
    c = parse_consensus(TEXT)
    c.relay.clear()
    empty = summary(c)
    assert empty["relay"] == 0
    assert empty["total_bandwidth"] == 0
    assert empty["exit_bandwidth_share"] is None
    assert empty["guard_bandwidth_share"] is None

    c = parse_consensus(TEXT)
    for relay in c.relay:
        relay.bandwidth = 0
    zero = summary(c)
    assert zero["total_bandwidth"] == 0
    assert zero["exit_bandwidth_share"] is None
    assert zero["guard_bandwidth_share"] is None


def test_invalid_request_counts_and_fractions():
    """无效计数和非有限覆盖比例不可用于估算。"""
    for requests in (-1, True, 1.5):
        with pytest.raises(ValueError):
            estimate_users(requests, 0.5)
    assert estimate_users(0, 0.1) == 0
    assert estimate_users(0, 1.1) == 0
    assert estimate_users(1000, float("nan")) is None
    assert estimate_users(1000, float("inf")) is None
    assert estimate_users(1000, -float("inf")) is None
    assert estimate_users(1000, True) is None


def test_invalid_rounding_inputs():
    """舍入步长必须是正偶整数。"""
    for step in (0, -2, 3, True):
        with pytest.raises(ValueError):
            remove_rounding(16, step)
    for value in (-1, True, 1.5):
        with pytest.raises(ValueError):
            remove_rounding(value)
    assert remove_rounding(16, 4) == 14
