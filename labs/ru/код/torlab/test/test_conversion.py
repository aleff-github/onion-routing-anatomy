# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
import base64

import pytest

from torlab.channel import ChannelError
from torlab.conversion import verify_crosscert

# Relay test004r из лабораторной сети (описание от 23 сентября 2026 года).
NTOR = "DaxPE+Grnjex2Hmv+5qutl5dIX4La2jF6MIL7IK6+3E"
CERT = base64.b64decode(
    "AQoAB5kbAZIzyIAwdjhbBic7sLE/ijEvxJfaq5RNv+D+VryL5swvAP3E4+R2wtel"
    "Dy46jK1zCpicy5JBvWZbuavhz2jJfRXh/t5g+lnh0NKGFzxeXZiroUDIHavjV+S0"
    "8f+YbkbdPwk=")
IDENTITY = "kjPIgDB2OFsGJzuwsT+KMS/El9qrlE2/4P5WvIvmzC8"


def test_valid_crosscert(monkeypatch):
    # Исторический сертификат: действовал 23.09.2026, истёк 21.10.2026.
    monkeypatch.setattr("torlab.channel.time.time", lambda: 1790164800)
    key = verify_crosscert(NTOR, 0, CERT)
    assert base64.b64encode(key).decode().rstrip("=") == IDENTITY


def test_wrong_sign():
    with pytest.raises(ChannelError):
        verify_crosscert(NTOR, 1, CERT)

def test_expired_crosscert(monkeypatch):
    # Срок действия исторического сертификата истёк 21.10.2026 в 19:00 UTC.
    monkeypatch.setattr("torlab.channel.time.time", lambda: 1792670400)
    with pytest.raises(ValueError, match="истёк"):
        verify_crosscert(NTOR, 0, CERT)


def test_invalid_crosscert_fields(monkeypatch):
    monkeypatch.setattr("torlab.channel.time.time", lambda: 1790164800)
    with pytest.raises(ValueError):
        verify_crosscert(NTOR, 2, CERT)
    with pytest.raises(ValueError):
        verify_crosscert("AQ==", 0, CERT)
    c = bytearray(CERT)
    c[1] = 4  # Сертификат NTOR_CC_IDENTITY должен иметь тип 0x0A.
    with pytest.raises(ValueError):
        verify_crosscert(NTOR, 0, bytes(c))
