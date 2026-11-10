# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Лабораторная работа 17 (глава 27): лимит в восемь RELAY_EARLY существовал до 2014 года; после атаки запретили ячейки в направлении клиента.
# Создать односкачковую цепь к 004r и отправить N ячеек RELAY_EARLY с сообщением DROP,
# которое ретранслятор молча отбрасывает, затем запросить соединение с каталогом,
# чтобы проверить, осталась ли цепь активной.
import sys
from torlab.cells import Cell, CellCommand, RelayCommand, RelayMessage
from torlab.circuit import Circuit, CircuitError, build
from torlab.laboratory import relay


def test_destination(n: int) -> str:
    """Ненормативный пример RELAY_EARLY с DROP; только приватный узел 004r."""
    if n not in (8, 9):
        raise ValueError("Допускаются только 8 или 9 ячеек RELAY_EARLY.")
    circ = build([relay("004r")], cc=False)
    try:
        for _ in range(n):
            # Согласно tor-spec, клиент не должен отправлять DROP внутри RELAY_EARLY.
            body = circ.crypto.encrypt(RelayMessage(RelayCommand.DROP, 0), None)
            circ.channel.send(Cell(circ.circ_id, CellCommand.RELAY_EARLY, body))
        circ.send(RelayMessage(RelayCommand.BEGIN_DIR, 1))
        _, response = circ.receive()
        return RelayCommand(response.command).name
    except CircuitError as exc:
        # Диагностика уже локализована в torlab.circuit.
        return str(exc)
    finally:
        circ.channel.sock.close()


def main() -> int:
    values = list(map(int, sys.argv[1:])) if len(sys.argv) > 1 else [8, 9]
    if not values or any(n not in (8, 9) for n in values) or len(values) != len(set(values)):
        raise SystemExit("Допускаются только 8 или 9 ячеек RELAY_EARLY.")
    results = {}
    for n in values:
        results[n] = test_destination(n)
        print(f"{n} ячеек RELAY_EARLY -> {results[n]}")
    # Учебное воспроизведение исторического наблюдения, а не требование MUST протокола.
    return 0 if all(results[n] == ("CONNECTED" if n == 8 else "цепочка уничтожена, причина 1") for n in values) else 1

if __name__ == "__main__":
    raise SystemExit(main())
