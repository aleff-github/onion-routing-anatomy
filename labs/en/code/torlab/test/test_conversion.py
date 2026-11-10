# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
import base64

import pytest

from torlab.channel import ChannelError
from torlab.conversion import verify_crosscert

# Relay test004r from the laboratory network (descriptor from 23 September 2026).
NTOR = "DaxPE+Grnjex2Hmv+5qutl5dIX4La2jF6MIL7IK6+3E"
CERT = base64.b64decode(
    "AQoAB5kbAZIzyIAwdjhbBic7sLE/ijEvxJfaq5RNv+D+VryL5swvAP3E4+R2wtel"
    "Dy46jK1zCpicy5JBvWZbuavhz2jJfRXh/t5g+lnh0NKGFzxeXZiroUDIHavjV+S0"
    "8f+YbkbdPwk=")
IDENTITY = "kjPIgDB2OFsGJzuwsT+KMS/El9qrlE2/4P5WvIvmzC8"


def test_valid_crosscert(monkeypatch):
    # Historical certificate: valid on 2026-09-23, expired on 2026-10-21.
    monkeypatch.setattr("torlab.channel.time.time", lambda: 1790164800)
    key = verify_crosscert(NTOR, 0, CERT)
    assert base64.b64encode(key).decode().rstrip("=") == IDENTITY


def test_wrong_sign():
    with pytest.raises(ChannelError):
        verify_crosscert(NTOR, 1, CERT)

def test_expired_crosscert(monkeypatch):
    # The historic signed fixture expired at 2026-10-21T19:00:00Z.
    monkeypatch.setattr("torlab.channel.time.time", lambda: 1792670400)
    with pytest.raises(ValueError, match="expired"):
        verify_crosscert(NTOR, 0, CERT)


def test_invalid_crosscert_fields(monkeypatch):
    monkeypatch.setattr("torlab.channel.time.time", lambda: 1790164800)
    with pytest.raises(ValueError):
        verify_crosscert(NTOR, 2, CERT)
    with pytest.raises(ValueError):
        verify_crosscert("AQ==", 0, CERT)
    c = bytearray(CERT)
    c[1] = 4  # The NTOR_CC_IDENTITY certificate must have type 0x0A.
    with pytest.raises(ValueError):
        verify_crosscert(NTOR, 0, bytes(c))
