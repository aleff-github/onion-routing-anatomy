#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 18 — diagnóstico SOCKS en una red Tor privada.

Utiliza localhost y el cliente 008c de la red privada Chutney.
Los avisos de TestSocks NO demuestran por sí solos una fuga DNS real.
"""
from __future__ import annotations

import http.server
from pathlib import Path
import re
import subprocess
import threading
import time

URL = "http://localhost:8080/"
SOCKS = "127.0.0.1:9008"
PUERTO_CONTROL = 8008
PUERTO_HTTP = 8080
OPCIONES = ("--socks5", "--socks5-hostname")
CLIENTE_PRIVADO = Path("/lab/net/nodes/008c")


class RespuestaLocal(http.server.BaseHTTPRequestHandler):
    """Devuelve un texto fijo: nunca publica archivos del volumen /lab."""
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        cuerpo = b"Laboratorio privado de Tor\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def log_message(self, formato, *argumentos):
        pass


def validar_entorno() -> None:
    """Rechaza ejecuciones fuera de la topología de laboratorio prevista."""
    if (not CLIENTE_PRIVADO.is_dir()
            or not Path("/lab/chutney/networks/book").is_file()):
        raise RuntimeError(
            "Se requiere Chutney privado con el cliente 008c activo. "
            "Inicia la topología book antes del experimento."
        )


def codigo_http(salida: str) -> str:
    """Acepta un código HTTP de tres cifras, incluido el marcador 000."""
    codigo = salida.strip()
    return codigo if re.fullmatch(r"\d{3}", codigo) else "000"


def aviso_socks(mensajes: list[str], fragmento: str) -> str:
    """Exige el diagnóstico de Tor que corresponde a cada opción SOCKS."""
    return next((m for m in mensajes
                 if fragmento.casefold() in m.casefold()), "")


def solicitar(opcion: str) -> tuple[str, int]:
    """Devuelve código HTTP y estado de curl; nunca permite otros destinos."""
    if opcion not in OPCIONES:
        raise ValueError("Opción SOCKS no permitida en este laboratorio")
    resultado = subprocess.run(
        ["curl", "-4", "--silent", "--show-error", "--output", "/dev/null",
         "--write-out", "%{http_code}", "--max-time", "20",
         "--noproxy", "", opcion, SOCKS, URL],
        capture_output=True, text=True, timeout=25, check=False,
    )
    return codigo_http(resultado.stdout), resultado.returncode


def restaurar_configuracion(controlador, originales: dict[str, str | None]) -> None:
    """Devuelve las opciones del ControlPort a sus valores previos."""
    for nombre, valor in originales.items():
        if valor is None:
            controlador.reset_conf(nombre)
        else:
            controlador.set_conf(nombre, valor)


def evaluar_resultados(
    datos: dict[str, tuple[str, int]], avisos: dict[str, str]
) -> dict[str, bool]:
    """Comprueba los avisos observados y el rechazo efectivo de SafeSocks."""
    return {
        "aviso sobre dirección IP local": (
            datos.get("--socks5") == ("200", 0)
            and "ip address" in avisos.get("--socks5", "").casefold()
        ),
        "aviso sobre resolución DNS delegada a Tor": (
            datos.get("--socks5-hostname") == ("200", 0)
            and "dns resolution" in avisos.get("--socks5-hostname", "").casefold()
        ),
        "rechazo por SafeSocks": (
            datos.get("--socks5 SafeSocks", ("", 0))[0] == "000"
            and datos.get("--socks5 SafeSocks", ("", 0))[1] != 0
        ),
    }


def comparar_socks(controlador, tipo_notice, tipo_warn, *,
                   solicitud=solicitar, esperar=time.sleep, mostrar=print) -> bool:
    """Compara los tres casos y restaura la configuración aun si falla curl."""
    mensajes: list[str] = []

    def registrar(evento):
        mensajes.append(evento.message)

    originales = {
        nombre: controlador.get_conf(nombre, default=None)
        for nombre in ("TestSocks", "SafeSocks")
    }
    escuchando = False
    try:
        controlador.add_event_listener(registrar, tipo_notice, tipo_warn)
        escuchando = True
        controlador.set_options({"TestSocks": "1", "SafeSocks": "0"})
        resultados: dict[str, tuple[str, int]] = {}
        avisos: dict[str, str] = {}
        for opcion, fragmento in (("--socks5", "IP address"),
                                  ("--socks5-hostname", "DNS resolution")):
            inicio = len(mensajes)
            resultados[opcion] = solicitud(opcion)
            esperar(1)
            avisos[opcion] = aviso_socks(mensajes[inicio:], fragmento)
            mostrar(f"{opcion:18s} HTTP {resultados[opcion][0]}  "
                    f"Tor: {avisos[opcion][:110] or 'sin aviso'}")

        controlador.set_conf("SafeSocks", "1")
        resultados["--socks5 SafeSocks"] = solicitud("--socks5")
        mostrar(f"{'--socks5 SafeSocks':18s} "
                f"HTTP {resultados['--socks5 SafeSocks'][0]}")
        verificaciones = evaluar_resultados(resultados, avisos)
        for nombre, correcto in verificaciones.items():
            mostrar(f"Comprobación {nombre}: "
                    f"{'CORRECTA' if correcto else 'NO VERIFICADA'}")
        return all(verificaciones.values())
    finally:
        try:
            restaurar_configuracion(controlador, originales)
        finally:
            if escuchando:
                controlador.remove_event_listener(registrar)


def ejecutar() -> int:
    validar_entorno()
    # Importación diferida: las pruebas offline no necesitan instalar Stem.
    from stem.control import Controller, EventType

    servidor = http.server.ThreadingHTTPServer(
        ("127.0.0.1", PUERTO_HTTP), RespuestaLocal
    )
    servidor.daemon_threads = True
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    try:
        with Controller.from_port(address="127.0.0.1",
                                  port=PUERTO_CONTROL) as controlador:
            controlador.authenticate()
            correcto = comparar_socks(
                controlador, EventType.NOTICE, EventType.WARN
            )
        return 0 if correcto else 1
    finally:
        servidor.shutdown()
        servidor.server_close()
        hilo.join()


if __name__ == "__main__":
    raise SystemExit(ejecutar())
