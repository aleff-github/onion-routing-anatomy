# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
from pathlib import Path

from torlab.cells import CellCommand
from torlab.traffic import cells_from_follow


def test_real_sequence():
    text = (Path(__file__).parent / "data" / "follow-tls.txt").read_text()
    seq = [(v, CellCommand(c.command).name) for v, c, _ in cells_from_follow(text)]
    assert seq == [("client", "VERSIONS"), ("relay", "VERSIONS"), ("relay", "CERTS"),
                   ("relay", "AUTH_CHALLENGE"), ("relay", "NETINFO"), ("client", "NETINFO"),
                   ("client", "CREATE2"), ("relay", "CREATED2")]
