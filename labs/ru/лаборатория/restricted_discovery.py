# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Лабораторная работа 13: авторизация клиентов X25519 в частной сети Tor.

Безопасность: ранее созданные каталоги авторизации не перезаписываются.
Удаляются только каталоги этой попытки. После прерывания нужна ручная проверка.
"""
from __future__ import annotations

import base64
import re
import shutil
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

LAB = Path(__file__).resolve().parent
NODES = LAB / "net" / "nodes"
SERVICE, CLIENT = NODES / "009h", NODES / "008c"
HS, AUTH = SERVICE / "restricted_service", CLIENT / "onion_auth"
CONTAINER, SOCKS = "torbook-network", "127.0.0.1:9008"
HOST = "127.0.0.1:8080"
ONION = re.compile(r"[a-z2-7]{56}\.onion\Z")


def b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def internal_directory(node: Path) -> str:
    match = re.search(r"(?m)^DataDirectory\s+(\S+)\s*$", (node / "torrc").read_text())
    if match is None:
        raise RuntimeError("Отсутствует DataDirectory" + ": " + node.name)
    return match.group(1)


def preflight() -> tuple[str, str, str, str]:
    service_torrc, client_torrc = SERVICE / "torrc", CLIENT / "torrc"
    original_service = service_torrc.read_text()
    original_client = client_torrc.read_text()
    if HS.exists() or AUTH.exists():
        raise RuntimeError("Уже существует каталог авторизации: проверьте состояние частной сети перед повторным запуском")
    if re.search(r"(?m)^HiddenServiceDir\s+\S*/restricted_service\s*$", original_service) or (
        re.search(r"(?m)^ClientOnionAuthDir\s+", original_client)
    ):
        raise RuntimeError("В torrc уже есть настройки авторизации")
    return original_service, original_client, internal_directory(SERVICE), internal_directory(CLIENT)


def hup(node: Path) -> None:
    """Проверить PID и командную строку нужного узла, затем отправить HUP только ему."""
    node_name = node.name
    if node_name not in ("009h", "008c"):
        raise ValueError("Неожиданный узел")
    command = (
        'pid=$(cat /lab/net/nodes/' + node_name + '/pid) || exit 1; '
        'case "$pid" in ""|*[!0-9]*) exit 1;; esac; '
        'args=$(ps -p "$pid" -o args=) || exit 1; '
        'case "$args" in *' + node_name + '/torrc*) kill -HUP "$pid";; *) exit 1;; esac'
    )
    subprocess.run(["docker", "exec", CONTAINER, "sh", "-c", command],
                   check=True, timeout=15)


def curl(address: str) -> str:
    """Использовать только адрес onion v3 через SOCKS частного клиента."""
    if not ONION.fullmatch(address):
        raise ValueError("Некорректный адрес onion v3")
    result = subprocess.run(
        ["docker", "exec", CONTAINER, "curl", "--silent", "--output", "/dev/null",
         "--write-out", "%{http_code}", "--max-time", "60", "--noproxy", "",
         "--socks5-hostname", SOCKS, f"http://{address}/"],
        capture_output=True, text=True, timeout=75
    )
    status = result.stdout.strip()
    return status if result.returncode == 0 and re.fullmatch(r"\d{3}", status) else "000"


def wait_address(attempts: int = 30) -> str:
    for _ in range(attempts):
        filename = HS / "hostname"
        if filename.is_file():
            address = filename.read_text().strip()
            if ONION.fullmatch(address):
                return address
        time.sleep(1)
    raise RuntimeError("Не появился корректный адрес onion v3")


def main() -> None:
    original_service, original_client, service_path, client_path = preflight()
    service_torrc, client_torrc = SERVICE / "torrc", CLIENT / "torrc"
    service_modified = client_modified = False
    service_created = client_created = False
    try:
        keypair = X25519PrivateKey.generate()
        priv = keypair.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pub = keypair.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        HS.mkdir(mode=0o700)
        service_created = True
        authorized = HS / "authorized_clients"
        authorized.mkdir(mode=0o700)
        public_file = authorized / "alice.auth"
        public_file.write_text(f"descriptor:x25519:{b32(pub)}\n")
        public_file.chmod(0o600)
        if not public_file.is_file() or not public_file.stat().st_size:
            raise RuntimeError("Отсутствует публичный файл .auth")

        service_modified = True
        service_torrc.write_text(
            original_service.rstrip("\n")
            + f"\nHiddenServiceDir {service_path}/restricted_service\n"
            + f"HiddenServicePort 80 {HOST}\n"
        )
        hup(SERVICE)
        address = wait_address()

        AUTH.mkdir(mode=0o700)
        client_created = True
        client_modified = True
        client_torrc.write_text(original_client.rstrip("\n")
                                + f"\nClientOnionAuthDir {client_path}/onion_auth\n")
        hup(CLIENT)
        time.sleep(20)
        without = curl(address)
        print("сервис с ограниченным обнаружением" + ": " + address)
        print("без ключа" + ": " + without)

        private_file = AUTH / "alice.auth_private"
        private_file.write_text(f"{address.removesuffix('.onion')}:descriptor:x25519:{b32(priv)}\n")
        private_file.chmod(0o600)
        hup(CLIENT)
        time.sleep(3)
        with_key = curl(address)
        print("с ключом" + ": " + with_key)
        if without != "000" or with_key != "200":
            raise RuntimeError("результат не подтверждён" + f": {without} / {with_key}")
    finally:
        # Восстановить исходные torrc до удаления временных каталогов.
        if client_modified:
            client_torrc.write_text(original_client)
        if service_modified:
            service_torrc.write_text(original_service)
        restored = True
        for node, changed in ((CLIENT, client_modified), (SERVICE, service_modified)):
            if changed:
                try:
                    hup(node)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
                    restored = False
                    print("Не удалось отправить HUP после восстановления" + f" {node.name}: {exc}")
        if restored:
            if client_created:
                shutil.rmtree(AUTH)
            if service_created:
                shutil.rmtree(HS)
        else:
            # Сохранить ключи до проверки работающего экземпляра Tor.
            raise RuntimeError("Не удалось перезагрузить Tor: проверьте состояние частной сети")


if __name__ == "__main__":
    main()
