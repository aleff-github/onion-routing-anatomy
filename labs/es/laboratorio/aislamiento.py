#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 11 — aislamiento de flujos con Stem y ControlPort de la red privada.

Solo genera solicitudes HTTP contra 127.0.0.1:8080 a través del SOCKS
127.0.0.1:9008 del cliente Chutney 008c. No utiliza la red Tor pública.
"""
from __future__ import annotations

import re
import subprocess
import time

DESTINO = "127.0.0.1:8080"
SOCKS = "127.0.0.1:9008"
PUERTO_CONTROL = 8008
CREDENCIALES = ("site-a.example:x1", "site-a.example:x1", "site-b.example:x2", None)


def es_flujo_de_prueba(evento) -> bool:
    """Ignora los flujos de directorio y cualquier destino ajeno al experimento."""
    return str(getattr(evento, "status", "")) == "SUCCEEDED" and getattr(evento, "target", None) == DESTINO


def nombre_tunel(estado_circuitos: str, circuito: str) -> str:
    """Etiqueta un túnel por los primeros ocho caracteres de CONFLUX_ID.
    Es una etiqueta abreviada: identificadores distintos pueden compartir prefijo."""
    for fila in estado_circuitos.splitlines():
        if fila.split(" ", 1)[0] == str(circuito):
            coincidencia = re.search(r"\bCONFLUX_ID=(\w+)", fila)
            return f"conflux {coincidencia.group(1)[:8]}" if coincidencia else f"circuito {circuito}"
    return f"circuito {circuito}"


def hay_conflux_completo(estado_circuitos: str) -> bool:
    """Dos ramas BUILT deben compartir un mismo identificador Conflux."""
    identificadores = re.findall(r"^\d+ BUILT .*CONFLUX_ID=(\w+)", estado_circuitos, re.M)
    return any(identificadores.count(identificador) >= 2 for identificador in set(identificadores))


def segundos_retraso_newnym(mensaje: str) -> int:
    """Obtiene el aplazamiento que anuncia tor; cero significa que no consta."""
    coincidencia = re.search(r"Rate limiting NEWNYM request: delaying by (\d+) second", mensaje)
    return int(coincidencia.group(1)) if coincidencia else 0


def validar_resultados(tuneles: list[str], posterior_newnym: str) -> dict[str, bool]:
    """Compara las etiquetas observadas, sin utilizar datos de red.
    La coincidencia de prefijos Conflux no prueba por sí sola identidad completa."""
    if len(tuneles) != 4 or any(t == "?" for t in (*tuneles, posterior_newnym)):
        return {"reutilización": False, "aislamiento": False, "sin credenciales": False, "NEWNYM": False}
    return {
        "reutilización": tuneles[0] == tuneles[1],
        "aislamiento": tuneles[0] != tuneles[2],
        "sin credenciales": tuneles[0] != tuneles[3],
        "NEWNYM": posterior_newnym != tuneles[0],
    }


def esperar_conflux(controlador, segundos: int = 30) -> bool:
    """Espera un túnel Conflux completo cuando esté disponible."""
    for _ in range(segundos * 2):
        if hay_conflux_completo(controlador.get_info("circuit-status")):
            return True
        time.sleep(0.5)
    return False


def solicitar(controlador, asignaciones: list, credenciales: str | None = None):
    """Usa el último STREAM SUCCEEDED por si tor reintenta el flujo en otro circuito."""
    asignaciones.clear()
    orden = ["curl", "--noproxy", "", "--silent", "--show-error", "--fail", "--max-time", "15",
             "-o", "/dev/null", "--socks5-hostname", SOCKS, f"http://{DESTINO}/"]
    if credenciales:
        orden[1:1] = ["--proxy-user", credenciales]
    subprocess.run(orden, check=True, timeout=20)
    for _ in range(20):
        if asignaciones:
            break
        time.sleep(0.5)
    if not asignaciones:
        return "?", []
    circuito = asignaciones[-1][1]
    return (
        nombre_tunel(controlador.get_info("circuit-status"), circuito),
        [salto[1] for salto in controlador.get_circuit(circuito).path],
    )


def nueva_identidad(controlador, avisos: list[str], anunciar: bool = False) -> None:
    """Respeta el aplazamiento de NEWNYM (límite de frecuencia impuesto por tor)."""
    avisos.clear()
    controlador.signal("NEWNYM")
    time.sleep(2)
    for mensaje in list(avisos):
        retraso = segundos_retraso_newnym(mensaje)
        if retraso:
            if anunciar:
                print(f"(NEWNYM aplazado {retraso} s)")
            time.sleep(retraso + 1)


def ejecutar() -> int:
    """Realiza el experimento en el cliente 008c de la red privada."""
    from stem.control import Controller, EventType

    asignaciones, avisos = [], []
    def al_recibir_flujo(evento):
        if es_flujo_de_prueba(evento):
            asignaciones.append((evento.id, evento.circ_id, evento.target))

    with Controller.from_port(address="127.0.0.1", port=PUERTO_CONTROL) as controlador:
        controlador.authenticate()
        controlador.add_event_listener(al_recibir_flujo, EventType.STREAM)
        controlador.add_event_listener(lambda evento: avisos.append(evento.message), EventType.NOTICE)
        nueva_identidad(controlador, avisos)
        if not esperar_conflux(controlador):
            print("Aviso: no se detectó un par Conflux completo; se observarán circuitos individuales.")
        tuneles = []
        for credenciales in CREDENCIALES:
            tunel, camino = solicitar(controlador, asignaciones, credenciales)
            tuneles.append(tunel)
            nombre = credenciales.split(":", 1)[0] if credenciales else "-"
            print(f"credenciales {nombre:15s} -> {tunel:22s} {camino}")
        nueva_identidad(controlador, avisos, anunciar=True)
        posterior, _ = solicitar(controlador, asignaciones, CREDENCIALES[0])
        print(f"después de NEWNYM, site-a.example -> {posterior}")

    comprobaciones = validar_resultados(tuneles, posterior)
    for nombre, cumple in comprobaciones.items():
        print(f"Comprobación {nombre}: {'CORRECTA' if cumple else 'NO VERIFICADA'}")
    return 0 if all(comprobaciones.values()) else 1


if __name__ == "__main__":
    raise SystemExit(ejecutar())
