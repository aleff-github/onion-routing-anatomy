# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Laboratory 17 (Chapter 27): the eight-cell RELAY_EARLY limit predates 2014; the 2014 fix rejects client-bound cells.
# Build a one-hop circuit to 004r; send N RELAY_EARLY cells carrying a DROP message
# (which the relay silently discards), then request a directory connection to see
# whether the circuit is still alive.
import sys
from torlab.cells import Cell, CellCommand, RelayCommand, RelayMessage
from torlab.circuit import Circuit, CircuitError, build
from torlab.laboratory import relay


def test_destination(n: int) -> str:
    """Intentionally non-conforming RELAY_EARLY+DROP; private node 004r only."""
    if n not in (8, 9):
        raise ValueError("Only 8 or 9 RELAY_EARLY cells are allowed in this experiment.")
    circ = build([relay("004r")], cc=False)
    try:
        for _ in range(n):
            # DROP inside RELAY_EARLY is NOT legal client behavior in tor-spec.
            body = circ.crypto.encrypt(RelayMessage(RelayCommand.DROP, 0), None)
            circ.channel.send(Cell(circ.circ_id, CellCommand.RELAY_EARLY, body))
        circ.send(RelayMessage(RelayCommand.BEGIN_DIR, 1))
        _, response = circ.receive()
        return RelayCommand(response.command).name
    except CircuitError as exc:
        return str(exc)
    finally:
        circ.channel.sock.close()


def main() -> int:
    values = list(map(int, sys.argv[1:])) if len(sys.argv) > 1 else [8, 9]
    if not values or any(n not in (8, 9) for n in values) or len(values) != len(set(values)):
        raise SystemExit("Only 8 or 9 RELAY_EARLY cells are allowed in this experiment.")
    results = {}
    for n in values:
        results[n] = test_destination(n)
        print(f"{n} cells RELAY_EARLY -> {results[n]}")
    # Educational reproduction of a historical observation, not a Tor MUST.
    return 0 if all(results[n] == ("CONNECTED" if n == 8 else "circuit destroyed, reason 1") for n in values) else 1

if __name__ == "__main__":
    raise SystemExit(main())
