#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 14: política de salida del repetidor 006e en la red privada.

Inserta temporalmente una regla de rechazo para 127.0.0.1:8080, comprueba
tres destinos en el bucle local y restaura el torrc original. Nunca probar
este script en repetidores reales ni con direcciones ajenas a 127.0.0.1.
"""
from __future__ import annotations

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
REPETIDOR_SALIDA = LAB / "net" / "nodes" / "006e"
CONTENEDOR = "torbook-es-network"
DIRECCION_LOCAL = "127.0.0.1"
PUERTO_PERMITIDO, PUERTO_BLOQUEADO, PUERTO_CERRADO = 8081, 8080, 9999


def insertar_regla_rechazo(original: str, puerto: int = PUERTO_BLOQUEADO) -> str:
    """Coloca la regla antes del primer ExitPolicy: gana la primera coincidencia."""
    if not 1 <= puerto <= 65535:
        raise ValueError("Puerto de destino fuera del rango TCP")
    regla = f"ExitPolicy reject {DIRECCION_LOCAL}:{puerto}"
    # Solo cuenta una línea de configuración, no un comentario que la cite.
    if re.search(rf"(?m)^[ \t]*{re.escape(regla)}[ \t]*(?:#.*)?$", original):
        raise ValueError("Ya existe la regla de rechazo en el torrc")
    coincidencia = re.search(r"(?m)^ExitPolicy\s+", original)
    if not coincidencia:
        raise ValueError("No existe una línea ExitPolicy en el torrc de 006e")
    return original[:coincidencia.start()] + regla + "\n" + original[coincidencia.start():]


def resultado_relay(comando: int, datos: bytes) -> str:
    """Interpreta CONNECTED y END sin modificar los códigos Tor."""
    if comando == RelayCommand.CONNECTED:
        return "CONNECTED"
    if comando != RelayCommand.END:
        return f"respuesta inesperada: {comando}"
    motivo = datos[0] if datos else 0
    detalle = ""
    if motivo == 4 and len(datos) >= 9:
        ip = ".".join(str(b) for b in datos[1:5])
        ttl = int.from_bytes(datos[5:9], "big")
        detalle = f" dirección={ip} TTL={ttl}"
    return f"END motivo={END_REASONS.get(motivo, motivo)}{detalle}"


def evaluar_resultados(resultados: dict[int, str]) -> dict[str, bool]:
    """Distingue el fallo de política, el éxito y el puerto sin servidor."""
    bloqueado = resultados.get(PUERTO_BLOQUEADO, "")
    permitido = resultados.get(PUERTO_PERMITIDO, "")
    cerrado = resultados.get(PUERTO_CERRADO, "")
    return {
        "rechazo": _motivo(bloqueado) == "EXITPOLICY",
        "permitido": permitido == "CONNECTED",
        "sin servidor": _motivo(cerrado) in ("MISC", "CONNECTREFUSED"),
    }


def _motivo(resultado: str) -> str | None:
    """Categoría exacta de un resultado END, sin aceptar prefijos falsificados."""
    coincidencia = re.fullmatch(r"END motivo=(\S+)(?: .*)?", resultado)
    return coincidencia.group(1) if coincidencia else None


def recargar() -> None:
    """Enviar HUP únicamente al PID de Tor 006e después de verificarlo."""
    comando = (
        'pid=$(cat /lab/net/nodes/006e/pid) || exit 1; '
        'case "$pid" in ""|*[!0-9]*) exit 1;; esac; '
        'args=$(ps -p "$pid" -o args=) || exit 1; '
        'case "$args" in *006e/torrc*) kill -HUP "$pid";; *) exit 1;; esac'
    )
    subprocess.run(["docker", "exec", CONTENEDOR, "sh", "-c", comando],
                   check=True, timeout=15)


def comprobar_destino(puerto: int) -> str:
    """Prueba solo 127.0.0.1 mediante un circuito privado de tres saltos."""
    if puerto not in (PUERTO_BLOQUEADO, PUERTO_PERMITIDO, PUERTO_CERRADO):
        raise ValueError("El destino debe ser uno de los tres puertos del laboratorio")
    circuito = build([relay("003r"), relay("005r"), relay("006e")])
    try:
        circuito.send(RelayMessage(RelayCommand.BEGIN, 1, begin_body(DIRECCION_LOCAL, puerto)))
        try:
            _, respuesta = circuito.receive()
        except CircuitError as exc:
            return str(exc)
        return resultado_relay(respuesta.command, respuesta.data)
    finally:
        circuito.channel.sock.close()



class RespuestaDePrueba(http.server.BaseHTTPRequestHandler):
    """Responde con contenido fijo sin publicar archivos locales ni claves."""
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        cuerpo = b"Prueba de salida privada de Tor\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def log_message(self, formato, *argumentos):
        pass


def iniciar_servidor(puerto: int, obligatorio: bool) -> http.server.ThreadingHTTPServer | None:
    try:
        servidor = http.server.ThreadingHTTPServer(
            (DIRECCION_LOCAL, puerto), RespuestaDePrueba
        )
    except OSError as exc:
        if obligatorio:
            raise RuntimeError(f"No se puede iniciar el servidor de prueba en {puerto}") from exc
        print(f"Aviso: el puerto {puerto} ya está ocupado; se usa el servidor local existente.")
        return None
    servidor.daemon_threads = True
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    return servidor


def puerto_cerrado_libre() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.25)
        return sock.connect_ex((DIRECCION_LOCAL, PUERTO_CERRADO)) != 0


def experimentar() -> bool:
    if not puerto_cerrado_libre():
        raise RuntimeError("El puerto 9999 tiene un servidor activo: la prueba negativa sería inválida")

    servidores: list[http.server.ThreadingHTTPServer] = []
    try:
        for puerto, obligatorio in ((PUERTO_PERMITIDO, True), (PUERTO_BLOQUEADO, False)):
            servidor = iniciar_servidor(puerto, obligatorio)
            if servidor:
                servidores.append(servidor)

        ruta = REPETIDOR_SALIDA / "torrc"
        original = ruta.read_text()
        modificado = insertar_regla_rechazo(original)
        actualizado = False
        try:
            # Considerar modificado desde antes de la escritura: también restaurar
            # si la escritura se interrumpe después de crear el archivo.
            actualizado = True
            ruta.write_text(modificado)
            recargar()
            time.sleep(3)
            resultados = {}
            for puerto in (PUERTO_BLOQUEADO, PUERTO_PERMITIDO, PUERTO_CERRADO):
                resultados[puerto] = comprobar_destino(puerto)
                print(f"{DIRECCION_LOCAL}:{puerto} -> {resultados[puerto]}")
            comprobaciones = evaluar_resultados(resultados)
            for nombre, pasa in comprobaciones.items():
                print(f"Comprobación {nombre}: {'CORRECTA' if pasa else 'NO VERIFICADA'}")
            return all(comprobaciones.values())
        finally:
            if actualizado:
                ruta.write_text(original)
                try:
                    recargar()
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
                    raise RuntimeError("No se pudo recargar el torrc original; inspeccionar 006e") from exc
    finally:
        for servidor in servidores:
            servidor.shutdown()
            servidor.server_close()


if __name__ == "__main__":
    raise SystemExit(0 if experimentar() else 1)
