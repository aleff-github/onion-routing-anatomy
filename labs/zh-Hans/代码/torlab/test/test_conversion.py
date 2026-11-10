# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
import base64

import pytest

from torlab.channel import ChannelError
from torlab.conversion import verify_crosscert

# 实验网络中的 test004r 中继（2026 年 9 月 23 日的描述符）。
NTOR = "DaxPE+Grnjex2Hmv+5qutl5dIX4La2jF6MIL7IK6+3E"
CERT = base64.b64decode(
    "AQoAB5kbAZIzyIAwdjhbBic7sLE/ijEvxJfaq5RNv+D+VryL5swvAP3E4+R2wtel"
    "Dy46jK1zCpicy5JBvWZbuavhz2jJfRXh/t5g+lnh0NKGFzxeXZiroUDIHavjV+S0"
    "8f+YbkbdPwk=")
IDENTITY = "kjPIgDB2OFsGJzuwsT+KMS/El9qrlE2/4P5WvIvmzC8"


def test_valid_crosscert(monkeypatch):
    # 历史证书：2026-09-23 有效，2026-10-21 已过期。
    monkeypatch.setattr("torlab.channel.time.time", lambda: 1790164800)
    key = verify_crosscert(NTOR, 0, CERT)
    assert base64.b64encode(key).decode().rstrip("=") == IDENTITY


def test_wrong_sign():
    with pytest.raises(ChannelError):
        verify_crosscert(NTOR, 1, CERT)

def test_expired_crosscert(monkeypatch):
    # 历史证书已于 2026-10-21 19:00 UTC 过期。
    monkeypatch.setattr("torlab.channel.time.time", lambda: 1792670400)
    with pytest.raises(ValueError, match="过期"):
        verify_crosscert(NTOR, 0, CERT)


def test_invalid_crosscert_fields(monkeypatch):
    monkeypatch.setattr("torlab.channel.time.time", lambda: 1790164800)
    with pytest.raises(ValueError):
        verify_crosscert(NTOR, 2, CERT)
    with pytest.raises(ValueError):
        verify_crosscert("AQ==", 0, CERT)
    c = bytearray(CERT)
    c[1] = 4  # NTOR_CC_IDENTITY 证书的类型必须为 0x0A。
    with pytest.raises(ValueError):
        verify_crosscert(NTOR, 0, bytes(c))
