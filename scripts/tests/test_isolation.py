# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Le protezioni di conftest.py funzionano davvero (altrimenti gli altri test non provano nulla)."""
from __future__ import annotations

import socket
import subprocess

import pytest


def test_connessioni_esterne_bloccate():
    with socket.socket() as s, pytest.raises(AssertionError, match="vietata"):
        s.connect(("192.0.2.1", 9001))              # TEST-NET-1: non viene mai contattato


@pytest.mark.parametrize("programma", ["docker", "tor", "chutney", "tcpdump", "tshark", "curl"])
def test_programmi_reali_bloccati(programma):
    with pytest.raises(AssertionError, match="vietato"):
        subprocess.run([programma, "--version"], capture_output=True)
