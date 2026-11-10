#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 13 — descubrimiento restringido en un servicio onion privado.

Crea un servicio temporal en 009h, autoriza una sola identidad X25519,
compara el acceso del cliente 008c antes y después de instalar la clave
y restaura los torrc originales. Nunca utilizar con servicios reales.
"""
from __future__ import annotations

import base64
import re
import shutil
import subprocess
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

LAB = Path(__file__).resolve().parent
NODOS = LAB / "net" / "nodes"
SERVICIO = NODOS / "009h"
CLIENTE = NODOS / "008c"
DIR_SERVICIO = SERVICIO / "restricted_service"
DIR_CLIENTE = CLIENTE / "onion_auth"
CONTENEDOR = "torbook-es-network"
SOCKS = "127.0.0.1:9008"
HTTP_LOCAL = "127.0.0.1:8080"


def base32_sin_relleno(valor: bytes) -> str:
    """Codificación requerida por los archivos de autorización de tor."""
    return base64.b32encode(valor).decode("ascii").rstrip("=")


def autorizacion_publica(clave: bytes) -> str:
    if len(clave) != 32:
        raise ValueError("La clave pública X25519 debe tener 32 bytes")
    return f"descriptor:x25519:{base32_sin_relleno(clave)}\n"


def autorizacion_privada(direccion: str, clave: bytes) -> str:
    if not re.fullmatch(r"[a-z2-7]{56}\.onion", direccion):
        raise ValueError("La dirección onion v3 no es válida")
    if len(clave) != 32:
        raise ValueError("La clave privada X25519 debe tener 32 bytes")
    return f"{direccion.removesuffix('.onion')}:descriptor:x25519:{base32_sin_relleno(clave)}\n"


def directorio_interno(nodo: Path) -> str:
    """Obtiene DataDirectory desde el torrc, no desde la ruta del anfitrión."""
    coincidencia = re.search(r"^DataDirectory\s+(\S+)", (nodo / "torrc").read_text(), re.M)
    if not coincidencia:
        raise RuntimeError(f"Falta DataDirectory en el nodo {nodo.name}")
    return coincidencia.group(1)


def validar_estado_inicial() -> tuple[str, str]:
    """Nunca sobrescribe directorios o configuraciones de autorización existentes."""
    original_servicio = (SERVICIO / "torrc").read_text()
    original_cliente = (CLIENTE / "torrc").read_text()
    if DIR_SERVICIO.exists() or DIR_CLIENTE.exists():
        raise RuntimeError("Existen directorios de autorización previos: inspecciona la red privada antes de continuar")
    if re.search(r"(?m)^HiddenServiceDir\s+\S*/restricted_service\s*$", original_servicio):
        raise RuntimeError("Ya existe una configuración restricted_service en el torrc")
    if re.search(r"(?m)^ClientOnionAuthDir\s+", original_cliente):
        raise RuntimeError("El cliente ya tiene un ClientOnionAuthDir: no se modificará")
    return original_servicio, original_cliente


def recargar(nodo: Path) -> None:
    """Envía HUP al proceso tor del nodo dentro del contenedor español."""
    # No enviar señales por coincidencia parcial del comando: comprobar el PID exacto.
    if nodo.name not in ("009h", "008c"):
        raise ValueError("Nodo inesperado")
    comando = (
        'pid=$(cat /lab/net/nodes/' + nodo.name + '/pid) || exit 1; '
        'case "$pid" in ""|*[!0-9]*) exit 1;; esac; '
        'args=$(ps -p "$pid" -o args=) || exit 1; '
        'case "$args" in *' + nodo.name + '/torrc*) kill -HUP "$pid";; *) exit 1;; esac'
    )
    subprocess.run(["docker", "exec", CONTENEDOR, "sh", "-c", comando],
                   check=True, timeout=15)


def consultar(direccion: str) -> str:
    """Solicita únicamente el .onion generado en esta red, por SOCKS local."""
    if not re.fullmatch(r"[a-z2-7]{56}\.onion", direccion):
        raise ValueError("Dirección onion inesperada")
    resultado = subprocess.run(
        ["docker", "exec", CONTENEDOR, "curl", "--silent", "--output", "/dev/null",
         "--write-out", "%{http_code}", "--max-time", "60",
         "--noproxy", "", "--socks5-hostname", SOCKS, f"http://{direccion}/"],
        capture_output=True, text=True, timeout=75,
    )
    codigo = resultado.stdout.strip()
    return codigo if resultado.returncode == 0 and re.fullmatch(r"\d{3}", codigo) else "000"


def esperar_direccion(intentos: int = 30) -> str:
    for _ in range(intentos):
        archivo = DIR_SERVICIO / "hostname"
        if archivo.is_file():
            direccion = archivo.read_text().strip()
            if re.fullmatch(r"[a-z2-7]{56}\.onion", direccion):
                return direccion
        time.sleep(1)
    raise RuntimeError("No apareció una dirección onion v3 en el servicio temporal")


def experimentar() -> bool:
    """Compara el resultado sin clave y con clave; restaura la red al finalizar."""
    original_s, original_c = validar_estado_inicial()
    # Las rutas temporales son exclusivas del experimento; nunca se elimina
    # una ruta que existiese antes de iniciar la prueba.
    servicio_modificado = cliente_modificado = False
    try:
        par = X25519PrivateKey.generate()
        privada = par.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        publica = par.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        DIR_SERVICIO.mkdir(mode=0o700)
        autorizados = DIR_SERVICIO / "authorized_clients"
        autorizados.mkdir(mode=0o700)
        fichero_publico = autorizados / "alice.auth"
        fichero_publico.write_text(autorizacion_publica(publica))
        fichero_publico.chmod(0o600)
        if not any(autorizados.glob("*.auth")):
            raise RuntimeError("El directorio authorized_clients está vacío")

        ruta_s = directorio_interno(SERVICIO)
        # Marcar antes de escribir: una escritura parcial también debe restaurarse.
        servicio_modificado = True
        (SERVICIO / "torrc").write_text(
            original_s.rstrip("\n")
            + f"\nHiddenServiceDir {ruta_s}/restricted_service\n"
            + f"HiddenServicePort 80 {HTTP_LOCAL}\n"
        )
        recargar(SERVICIO)
        direccion = esperar_direccion()

        DIR_CLIENTE.mkdir(mode=0o700)
        ruta_c = directorio_interno(CLIENTE)
        # Una escritura incompleta también requiere restaurar el torrc del cliente.
        cliente_modificado = True
        (CLIENTE / "torrc").write_text(
            original_c.rstrip("\n") + f"\nClientOnionAuthDir {ruta_c}/onion_auth\n"
        )
        recargar(CLIENTE)
        time.sleep(20)  # Publicación del descriptor en la red privada.
        sin_clave = consultar(direccion)
        print(f"servicio restringido: {direccion}")
        print(f"sin clave: {sin_clave}")

        fichero_privado = DIR_CLIENTE / "alice.auth_private"
        fichero_privado.write_text(autorizacion_privada(direccion, privada))
        fichero_privado.chmod(0o600)
        recargar(CLIENTE)
        time.sleep(3)
        con_clave = consultar(direccion)
        print(f"con clave: {con_clave}")
        correcto = sin_clave == "000" and con_clave == "200"
        print("Resultado: " + ("CORRECTO" if correcto else "NO VERIFICADO"))
        return correcto
    finally:
        # Restauración incluso si falla HUP, la publicación o curl.
        if servicio_modificado:
            (SERVICIO / "torrc").write_text(original_s)
        if cliente_modificado:
            (CLIENTE / "torrc").write_text(original_c)
        restaurado = True
        for nodo, modificado in ((CLIENTE, cliente_modificado),
                                 (SERVICIO, servicio_modificado)):
            if modificado:
                try:
                    recargar(nodo)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
                    restaurado = False
                    print(f"Aviso: no se pudo recargar {nodo.name} tras restaurar torrc: {exc}")
        if restaurado:
            # No ocultar fallos de limpieza: podrían quedar archivos con claves.
            for directorio in (DIR_CLIENTE, DIR_SERVICIO):
                if directorio.exists():
                    shutil.rmtree(directorio)
        else:
            # No borrar claves que el proceso Tor todavía podría estar utilizando.
            raise RuntimeError("Fallo al recargar Tor: inspeccionar manualmente claves y directorios")


if __name__ == "__main__":
    raise SystemExit(0 if experimentar() else 1)
