# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Лабораторная работа 14 (глава 22): правило политики выхода (ExitPolicy) и его последствия.
# Добавить в test006e запрет одного порта перед правилами, разрешающими 127.0.0.0/8,
# затем проверить три назначения. В конце всегда восстановить исходный torrc.
import http.server
import re
import socket
import subprocess
import threading
import time
from pathlib import Path

from torlab.cells import RelayCommand, RelayMessage
from torlab.circuit import CircuitError, build
from torlab.laboratory import relay
from torlab.stream import END_REASONS, begin_body

LAB = Path(__file__).resolve().parent
EXIT = LAB / "net" / "nodes" / "006e"
CONTAINER = "torbook-network"
OPEN_PORT, BLOCKED_PORT, NO_SERVER_PORT = 8081, 8080, 9999


class ФиксированныйОтвет(http.server.BaseHTTPRequestHandler):
    """Возвращает только тестовый текст, не раскрывая локальные файлы."""
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        body = "Приватная проверка политики выхода Tor\n".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass



def hup():
    # Проверять точный PID 006e, не искать процессы по произвольной подстроке.
    command = (
        'pid=$(cat /lab/net/nodes/006e/pid) || exit 1; '
        'case "$pid" in ""|*[!0-9]*) exit 1;; esac; '
        'args=$(ps -p "$pid" -o args=) || exit 1; '
        'case "$args" in *006e/torrc*) kill -HUP "$pid";; *) exit 1;; esac'
    )
    subprocess.run(["docker", "exec", CONTAINER, "sh", "-c", command],
                   check=True, timeout=15)


def test_destination(port: int) -> str:
    """Запрашивает локальный адрес через трёхузловой маршрут частной сети."""
    if port not in (OPEN_PORT, BLOCKED_PORT, NO_SERVER_PORT):
        raise ValueError("Для этого опыта разрешены только три заданных порта назначения")
    circ = build([relay("003r"), relay("005r"), relay("006e")])
    try:
        circ.send(RelayMessage(RelayCommand.BEGIN, 1, begin_body("127.0.0.1", port)))
        try:
            _, response = circ.receive()
        except CircuitError as error:
            return str(error)
        if response.command == RelayCommand.CONNECTED:
            return "CONNECTED"
        if response.command != RelayCommand.END:
            raise RuntimeError("Неожиданный ответ" + f": {response.command}")
        reason = response.data[0] if response.data else 1
        suffix = ""
        if reason == 4 and len(response.data) == 9:
            ip = ".".join(str(b) for b in response.data[1:5])
            suffix = f" адрес={ip} TTL={int.from_bytes(response.data[5:9], 'big')}"
        return f"END reason={END_REASONS.get(reason, reason)}{suffix}"
    finally:
        circ.channel.sock.close()


def main():
    # Не выполнять отрицательную пробу, если порт уже занят.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check:
        check.settimeout(0.25)
        if check.connect_ex(("127.0.0.1", 9999)) == 0:
            raise RuntimeError("На порту 9999 работает сервер: отрицательная проба будет некорректной")
    torrc = EXIT / "torrc"
    original = torrc.read_text()
    rule = "ExitPolicy reject 127.0.0.1:8080"
    if re.search(r"(?m)^\s*" + re.escape(rule) + r"\s*$", original):
        raise RuntimeError("Правило запрета уже существует")
    match = re.search(r"(?m)^ExitPolicy\s+", original)
    if match is None:
        raise RuntimeError("В torrc узла 006e нет директивы ExitPolicy")
    # Вставлять правило срезами строки, исключая ошибки escape-последовательностей.
    updated = original[:match.start()] + rule + "\n" + original[match.start():]
    servers = []
    modified = False
    try:
        for port in (8081, 8080):
            try:
                server = http.server.ThreadingHTTPServer(
                    ("127.0.0.1", port), ФиксированныйОтвет)
            except OSError as exc:
                if port == 8081:
                    raise RuntimeError("Порт 8081 занят: для положительной пробы нужен свободный порт") from exc
                # Порт 8080 может использоваться локальным тестовым HTTP-сервером.
                continue
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
            servers.append(server)
        try:
            # Отмечать изменение до записи, чтобы восстановить и неполный файл.
            modified = True
            torrc.write_text(updated)
            hup()
            time.sleep(3)
            results = {}
            for port in (8080, 8081, 9999):
                results[port] = test_destination(port)
                print(f"127.0.0.1:{port} -> {results[port]}")
            valid = (results[8080].startswith("END reason=EXITPOLICY")
                     and results[8081] == "CONNECTED"
                     and results[9999] in ("END reason=MISC",
                                            "END reason=CONNECTREFUSED"))
            if not valid:
                raise RuntimeError("Результаты лабораторных проверок не соответствуют ожидаемым категориям")
        finally:
            if modified:
                torrc.write_text(original)
                try:
                    hup()
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
                    raise RuntimeError("Не удалось загрузить исходный torrc: проверьте узел 006e") from exc
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
