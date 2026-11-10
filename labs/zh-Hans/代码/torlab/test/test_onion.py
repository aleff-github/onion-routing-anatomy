# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""实验 8 测试：使用 data/ 中私有实验网络的真实描述符。"""
from pathlib import Path

import pytest

from torlab.onion import (parse_descriptor, blinded_key, key_from_address,
                          onion_address, time_period_info)

DATA = Path(__file__).parent / "data"
ADDRESS = (DATA / "onion-descriptor.address").read_text().strip()
TEXT = (DATA / "onion-descriptor.txt").read_text()
PERIOD, DURATION = 3729540, 8          # 下载该描述符时所处的时间周期


def test_specification_addresses():
    for a in ("pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
              "sp3k262uwy4r2k3ycr5awluarykdpag6a7y33jxop4cs2lu5uz5sseqd.onion",
              "xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jyd.onion"):
        assert onion_address(key_from_address(a)) == a


def test_checksum_wrong():
    wrong = ADDRESS[:10] + ("a" if ADDRESS[10] != "a" else "b") + ADDRESS[11:]
    with pytest.raises(ValueError):
        key_from_address(wrong)


def test_real_descriptor():
    A = key_from_address(ADDRESS)
    d = parse_descriptor(TEXT, A, blinded_key(A, PERIOD, DURATION))
    assert d.duration_minutes == 180 and len(d.introduction_points) == 3


def test_wrong_period_rejected():
    A = key_from_address(ADDRESS)
    with pytest.raises(ValueError):
        parse_descriptor(TEXT, A, blinded_key(A, PERIOD + 1, DURATION))


def test_public_network_time():
    # 规范示例：2016-04-13 11:15:01 UTC → 周期 16903（每小时投票）。
    assert time_period_info(1460546101, 3600, test_network=False).period == 16903


from torlab import onion as _onion_checked


def test_sequence141_reject_invalid_onion_addresses():
    """拒绝无效 onion 地址和非规范点编码。"""
    with pytest.raises(ValueError):
        _onion_checked.onion_address(bytes(31))
    for invalid in ("example.onion", "a" * 56 + ".onion",
                    ADDRESS.removesuffix(".onion"),
                    "0" + ADDRESS[1:]):
        with pytest.raises(ValueError):
            _onion_checked.key_from_address(invalid)
    with pytest.raises(ValueError):
        _onion_checked._decode_point(bytes(31))
    with pytest.raises(ValueError):
        _onion_checked._decode_point(_onion_checked.P.to_bytes(32, "little"))
    with pytest.raises(ValueError):
        _onion_checked._decode_point((1 | (1 << 255)).to_bytes(32, "little"))


def test_sequence141_validate_time_and_hsdir_ring():
    """验证时间周期与 HSDir 环参数。"""
    with pytest.raises(ValueError):
        _onion_checked.time_period_info(1460546101, 0, False)
    with pytest.raises(ValueError):
        _onion_checked.time_period_info(-1, 3600, False)
    t = _onion_checked.time_period_info(1460546101, 3600, False)
    with pytest.raises(ValueError):
        _onion_checked.responsible_hsdirs(bytes(32), [], bytes(32), t)
    with pytest.raises(ValueError):
        _onion_checked.responsible_hsdirs(bytes(32), [("a", bytes(32))] * 6, bytes(32), t)
    names = [(str(i), bytes([i]) * 32) for i in range(1, 7)]
    groups = _onion_checked.responsible_hsdirs(bytes(32), names, bytes(32), t)
    assert len(groups) == 2
    assert len(set(groups[0] + groups[1])) == 6


def test_sequence141_validate_encrypted_layer_and_pem():
    """验证描述符层 MAC 和 PEM 封装。"""
    with pytest.raises(ValueError):
        _onion_checked._decrypt_layer(bytes(47), bytes(32), bytes(32), 1, b"hsdir-encrypted-data")
    with pytest.raises(ValueError):
        _onion_checked._decrypt_layer(bytes(48), bytes(32), bytes(32), 1, b"hsdir-encrypted-data")
    with pytest.raises(ValueError):
        _onion_checked._object_block("encrypted\n-----BEGIN MESSAGE-----\n!\n-----END MESSAGE-----", "encrypted")
    with pytest.raises(ValueError):
        _onion_checked._object_block("encrypted\n-----BEGIN MESSAGE-----\nYQ==", "encrypted")


def test_sequence141_validate_descriptor_fields_and_expiry():
    """验证描述符字段及可选证书过期检查。"""
    A = _onion_checked.key_from_address(ADDRESS)
    blinded = _onion_checked.blinded_key(A, PERIOD, DURATION)
    with pytest.raises(ValueError):
        _onion_checked.parse_descriptor(TEXT.replace("descriptor-lifetime 180", "descriptor-lifetime 1"), A, blinded)
    with pytest.raises(ValueError):
        _onion_checked.parse_descriptor(TEXT.replace("revision-counter 662427", "revision-counter 662427\nrevision-counter 662427"), A, blinded)
    with pytest.raises(ValueError, match="描述符签名证书已过期"):
        _onion_checked.parse_descriptor(TEXT, A, blinded,
                         check_expiration=True, reference_time=4102444800)
    with pytest.raises(ValueError):
        _onion_checked.download_descriptor(blinded, [])
