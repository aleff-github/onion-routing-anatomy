# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Laboratorio 16: correlación de tráfico sintético propio en una red privada.
# El identificador en claro solo se usa para evaluar, no es captura pasiva.
from __future__ import annotations

import math
import random
import socket
import socketserver
import statistics
import struct
import sys
import threading
import time

N, DURATION, BIN, BLOCK = 6, 20.0, 0.25, 2048
SERVER_PORT, SOCKS = 8095, ("127.0.0.1", 9008)
arrivals: dict[int, list[tuple[float, int]]] = {}
sends: dict[int, list[tuple[float, int]]] = {}
ground_truth: dict[int, int] = {}  # Solo se utiliza para evaluar, nunca para relacionar flujos.
flow_lock = threading.Lock()


def recv_exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        fragment = sock.recv(count - len(data))
        if not fragment:
            raise ConnectionError("Respuesta incompleta de SOCKS o del flujo")
        data.extend(fragment)
    return bytes(data)


class Receiver(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(40)
        try:
            # Identificador sintético usado exclusivamente para evaluar el resultado.
            index = struct.unpack(">I", recv_exact(self.request, 4))[0]
            if index >= N:
                return
            records: list[tuple[float, int]] = []
            with flow_lock:
                flow_id = len(arrivals)
                ground_truth[flow_id] = index
                arrivals[flow_id] = records
            while True:
                data = self.request.recv(65536)
                if not data:
                    return
                records.append((time.monotonic(), len(data)))
        except (ConnectionError, OSError):
            return


class LabServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def socks5(credentials: str) -> socket.socket:
    """SOCKS5 privado con lectura completa; destino fijo en localhost:8095."""
    user = credentials.encode("utf-8")
    if not 1 <= len(user) <= 255:
        raise ValueError("El nombre SOCKS debe tener de 1 a 255 bytes")
    sock = socket.create_connection(SOCKS, timeout=15)
    try:
        sock.settimeout(15)
        sock.sendall(b"\x05\x01\x02")
        if recv_exact(sock, 2) != b"\x05\x02":
            raise ConnectionError("Autenticación SOCKS5 por usuario y contraseña no disponible")
        sock.sendall(b"\x01" + bytes([len(user)]) + user + b"\x01x")
        if recv_exact(sock, 2) != b"\x01\x00":
            raise ConnectionError("Credenciales SOCKS5 rechazadas")
        sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1")
                     + struct.pack(">H", SERVER_PORT))
        version, status, reserved, atyp = recv_exact(sock, 4)
        if version != 5 or status != 0 or reserved != 0:
            raise ConnectionError(f"Conexión SOCKS5 fallida: {status}")
        if atyp == 1:
            recv_exact(sock, 4)
        elif atyp == 4:
            recv_exact(sock, 16)
        elif atyp == 3:
            recv_exact(sock, recv_exact(sock, 1)[0])
        else:
            raise ConnectionError("Tipo de dirección SOCKS5 inesperado")
        recv_exact(sock, 2)  # BND.PORT
        sock.settimeout(45)
        return sock
    except BaseException:
        sock.close()
        raise


def client(i: int, rng: random.Random, start: float) -> None:
    sends[i] = []
    # Credenciales SOCKS diferentes no garantizan circuitos diferentes.
    with socks5(f"flow-{i}") as sock:
        sock.sendall(struct.pack(">I", i))  # Identificador para evaluar, no para correlacionar.
        while time.monotonic() - start < DURATION:
            if rng.random() < 0.5:
                for _ in range(rng.randint(5, 40)):
                    sock.sendall(b"\0" * BLOCK)
                    sends[i].append((time.monotonic(), BLOCK))
            time.sleep(rng.uniform(0.2, 1.0))


def series(events, start):
    bins = [0] * int(DURATION / BIN + 20)
    for timestamp, size in events:
        if timestamp < start:            # int() truncaría hacia cero: -0.01 caería en el intervalo 0
            continue
        idx = int((timestamp - start) / BIN)
        if 0 <= idx < len(bins):
            bins[idx] += size
    return bins


def safe_correlation(a, b) -> float:
    """Una serie constante o ausente no permite calcular una correlación válida."""
    if len(a) != len(b) or len(a) < 2 or len(set(a)) < 2 or len(set(b)) < 2:
        return float("-inf")
    try:
        score = statistics.correlation(a, b)
    except (statistics.StatisticsError, ValueError):
        return float("-inf")
    return score if math.isfinite(score) else float("-inf")


def main() -> int:
    seed = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    arrivals.clear()
    sends.clear()
    ground_truth.clear()
    errors: list[tuple[int, Exception]] = []

    def worker(i: int, start: float) -> None:
        try:
            client(i, random.Random(seed * 100 + i), start)
        except Exception as exc:
            errors.append((i, exc))

    with LabServer(("127.0.0.1", SERVER_PORT), Receiver) as server:
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            start = time.monotonic()
            threads = [threading.Thread(target=worker, args=(i, start)) for i in range(N)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            time.sleep(3)
        finally:
            server.shutdown()
            server_thread.join()

    if errors:
        raise RuntimeError(f"Error en cliente {errors[0][0]}: {errors[0][1]}") from errors[0][1]
    if len(sends) != N or len(arrivals) != N:
        raise RuntimeError("Faltan flujos sintéticos")

    entry_series = {i: series(events, start) for i, events in sends.items()}
    exit_flow = {k: series(events, start) for k, events in arrivals.items()}
    correct = 0
    for i, entry in sorted(entry_series.items()):
        scores = {k: safe_correlation(entry, exit_) for k, exit_ in exit_flow.items()}
        if not any(math.isfinite(score) for score in scores.values()):
            raise RuntimeError("No hay series variables para comparar")
        best = max(scores, key=scores.get)
        matched = ground_truth[best] == i
        correct += int(matched)
        values = " ".join(f"{scores[k]:+.2f}" for k in sorted(exit_flow))
        label = "CORRECTO" if matched else "INCORRECTO"
        print(f"cliente {i}: {values}  -> flujo de salida {best} {label}")
    print(f"correspondencias correctas: {correct}/{len(entry_series)}")
    return 0 if correct >= 5 else 1


if __name__ == "__main__":
    raise SystemExit(main())
