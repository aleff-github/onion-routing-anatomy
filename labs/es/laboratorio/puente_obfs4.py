#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 10: comprobaciones de obfs4 exclusivamente en la red privada local.

No descarga puentes públicos ni intenta eludir filtros externos. Las capturas
deben generarse de manera independiente en la red de laboratorio del libro.
"""
from __future__ import annotations

import argparse
import re
import socket
import ssl
import subprocess
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parent
REGISTRO_CLIENTE = LAB / "net" / "nodes" / "011bc" / "notice.log"
CONTENEDOR = "torbook-es-network"
IP_PRIVADA = "127.0.0.1"
PUERTO_OBFS4 = 9909
PUERTO_OR = 5104
PUERTO_SOCKS = 9011
PUERTO_HTTP = 8080


def arranque_completo(registro: str) -> bool:
    """Comprueba el mensaje de bootstrap, sin inferir la salud de toda la red."""
    porcentajes = re.findall(r"Bootstrapped\s+(\d{1,3})%", registro)
    return bool(porcentajes) and int(porcentajes[-1]) == 100


def prefijo_tls(cadena_hex: str) -> bool:
    """Detecta un encabezado de registro TLS en el inicio de un segmento TCP.

    Es una heurística de laboratorio, no un clasificador definitivo de flujos.
    """
    try:
        contenido = bytes.fromhex(cadena_hex.strip().replace(":", ""))
    except ValueError:
        return False
    return len(contenido) >= 3 and contenido[0:2] == b"\x16\x03" and contenido[2] <= 4


def resumir_payloads(salida_tshark: str) -> tuple[int, int, str]:
    """Devuelve (segmentos de datos, prefijos parecidos a TLS, muestra hexadecimal)."""
    segmentos = [linea.strip() for linea in salida_tshark.splitlines() if linea.strip()]
    return len(segmentos), sum(prefijo_tls(s) for s in segmentos), segmentos[0][:48] if segmentos else ""


def nombre_captura_valido(nombre: str) -> bool:
    """Solo se permite un archivo dentro de laboratorio/net/, sin rutas arbitrarias."""
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.pcap(?:ng)?", nombre))


def ejecutar(comando: list[str], timeout: int = 30) -> str:
    resultado = subprocess.run(comando, capture_output=True, text=True, check=True, timeout=timeout)
    return resultado.stdout


def estado() -> int:
    if not REGISTRO_CLIENTE.is_file():
        print("No existe el registro del cliente 011bc. Inicia primero NETWORK=book-bridge.")
        return 1
    registro = REGISTRO_CLIENTE.read_text(errors="replace")
    if not arranque_completo(registro):
        print("El cliente 011bc todavía no registra Bootstrapped 100%. Revisa notice.log.")
        return 1
    print("Cliente del puente 011bc: arranque completo según notice.log.")
    print("Este resultado no certifica por sí solo la conexión HTTP ni la ofuscación.")
    return 0


def http_local() -> int:
    """Petición HTTP únicamente a 127.0.0.1 mediante el SOCKS del puente."""
    codigo = ejecutar([
        "docker", "exec", CONTENEDOR, "curl", "--silent", "--show-error",
        "--max-time", "15", "--noproxy", "",
        "--socks5-hostname", f"{IP_PRIVADA}:{PUERTO_SOCKS}",
        "-o", "/dev/null", "-w", "%{http_code}",
        f"http://{IP_PRIVADA}:{PUERTO_HTTP}/",
    ], timeout=25).strip()
    print(f"HTTP local a través de SOCKS del puente: {codigo}")
    if codigo != "200":
        print("No se ha obtenido HTTP 200. Comprueba el servidor local en el puerto 8080.")
        return 1
    return 0


def sondeo_tls() -> int:
    """Intento TLS controlado contra el puerto obfs4 local (nunca en Internet)."""
    with socket.create_connection((IP_PRIVADA, PUERTO_OBFS4), timeout=5) as conexion:
        conexion.settimeout(5)
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE
        try:
            with contexto.wrap_socket(conexion) as tls:
                print(f"Se negoció TLS ({tls.version()}): comportamiento inesperado para el puerto obfs4.")
                return 1
        except (TimeoutError, ssl.SSLError, ConnectionResetError, BrokenPipeError) as exc:
            print(f"No se completó un intercambio TLS en {IP_PRIVADA}:{PUERTO_OBFS4}: "
                  f"{type(exc).__name__}.")
            print("Esta observación por sí sola no demuestra resistencia al sondeo activo.")
            return 0


def analizar_captura(nombre: str) -> int:
    """Analiza una captura ya realizada; no genera tráfico ni toma capturas."""
    if not nombre_captura_valido(nombre):
        print("Nombre de captura no válido: usa un archivo .pcap o .pcapng dentro de net/.")
        return 1
    red = LAB / "net"
    captura = red / nombre
    # Los enlaces simbólicos, del archivo o del propio net/, pueden salir del laboratorio.
    if red.is_symlink() or captura.is_symlink() or not captura.is_file():
        print(f"Captura ausente o enlace simbólico no permitido: net/{nombre}")
        return 1
    for puerto in (PUERTO_OR, PUERTO_OBFS4):
        salida = ejecutar([
            "docker", "exec", "-u", "0", CONTENEDOR, "tshark",
            "-r", f"/lab/net/{nombre}", "-Y", f"tcp.dstport=={puerto} && tcp.len>0",
            "-T", "fields", "-e", "tcp.payload",
        ], timeout=60)
        segmentos, tls, muestra = resumir_payloads(salida)
        print(f"Puerto {puerto}: segmentos con datos={segmentos}; "
              f"prefijos compatibles con un registro TLS={tls}; primera muestra={muestra or '-'}")
    print("La detección por prefijo es orientativa; una captura vacía no valida el transporte.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Pruebas limitadas al laboratorio obfs4 local.")
    parser.add_argument("accion", choices=("estado", "http", "sondeo", "analizar"))
    parser.add_argument("--archivo", default="b1.pcap", help="Nombre de una captura en laboratorio/net/.")
    args = parser.parse_args()
    try:
        if args.accion == "estado":
            return estado()
        if args.accion == "http":
            return http_local()
        if args.accion == "sondeo":
            return sondeo_tls()
        return analizar_captura(args.archivo)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"Comprobación no completada: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
