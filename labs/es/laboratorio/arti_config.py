#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 20 — configuración de Arti para la red Tor privada del libro.

Lee las identidades de las tres autoridades de Chutney y genera net/arti/arti.toml.
El archivo permite a Arti conectarse a nuestra red, sin servidores públicos.
La configuración replica las opciones de Chutney: direcciones locales permitidas,
autoridades y fallbacks privados, sin restricciones /16 (todos usan 127.0.0.1).
No descarga, compila ni ejecuta Arti.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

LAB = Path(__file__).resolve().parent / "net"
NODES = LAB / "nodes"
ARTI = LAB / "arti"
VOTING_INTERVAL_SECONDS = 20  # V3AuthVotingInterval de la red Chutney


def campo(texto: str, expresion: str, nombre: str) -> str:
    """Lee un campo requerido y falla si la configuración está incompleta."""
    coincidencia = re.search(expresion, texto, re.M)
    if not coincidencia:
        raise ValueError(f"Falta {nombre} en los datos de la autoridad")
    return coincidencia.group(1)


def authorities_from_network(nodes: Path | None = None):
    """Lee las tres autoridades de la topología privada desde sus archivos."""
    nodos = nodes if nodes is not None else NODES
    for directorio in sorted(nodos.glob("00?a")):
        rsa = (directorio / "fingerprint").read_text(encoding="utf-8").split()[1]
        ed = (directorio / "fingerprint-ed25519").read_text(encoding="utf-8").split()[1]
        certificado = (directorio / "keys" / "authority_certificate").read_text(encoding="utf-8")
        v3 = campo(certificado, r"^fingerprint (\w+)", "fingerprint del certificado")
        torrc = (directorio / "torrc").read_text(encoding="utf-8")
        orport = campo(torrc, r"^OrPort \S*?:?(\d+)$", "OrPort")
        dirport = campo(torrc, r"^DirPort (\d+)$", "DirPort")
        yield rsa, ed, v3, orport, dirport


def generar_configuracion(authorities: list[tuple[str, str, str, str, str]],
                          arti_dir: Path) -> str:
    """Construye la configuración TOML para tres autoridades privadas.

    Claves TOML, nombres de tablas e identidades criptográficas no se traducen.
    """
    if len(authorities) != 3:
        raise ValueError(f"Se esperaban tres autoridades privadas, se encontraron {len(authorities)}")
    lista = lambda valores: "[" + ", ".join(valores) + "]"
    lineas = [
        "[proxy]", "socks_listen = 9150", "",
        "[storage]", f"cache_dir = {json.dumps(str(arti_dir / 'cache'))}",
        f"state_dir = {json.dumps(str(arti_dir / 'state'))}",
        f"port_info_file = {json.dumps(str(arti_dir / 'state' / 'public' / 'port_info.json'))}", "",
        "[path_rules]", "ipv4_subnet_family_prefix = 33",
        "ipv6_subnet_family_prefix = 129", "",
        "[address_filter]", "allow_local_addrs = true", "",
        "[override_net_params]",
        f"hsdir_interval = {12 * 2 * VOTING_INTERVAL_SECONDS // 60}", "",
        "[tor_network]", "fallback_caches = [",
        *[f'  {{ rsa_identity = "{rsa}", ed_identity = "{ed}", orports = ["127.0.0.1:{orp}"] }},'
          for rsa, ed, _, orp, _ in authorities],
        "]", "",
        "[tor_network.authorities]",
        "v3idents = " + lista(f'"{identidad[2]}"' for identidad in authorities),
    ]
    puertos = lista(f'["127.0.0.1:{autoridad[4]}"]' for autoridad in authorities)
    lineas += [f"uploads = {puertos}", f"downloads = {puertos}",
               f"votes = {puertos}", ""]
    return "\n".join(lineas)


def main() -> None:
    """Genera únicamente un archivo dentro de laboratorio/net/arti/ de esta edición."""
    if not NODES.is_dir():
        raise FileNotFoundError(
            "Falta laboratorio/net/nodes: inicia primero la topología privada book de Chutney"
        )
    autoridades = list(authorities_from_network())
    configuracion = generar_configuracion(autoridades, ARTI)
    ARTI.mkdir(parents=True, exist_ok=True)
    archivo = ARTI / "arti.toml"
    archivo.write_text(configuracion, encoding="utf-8")
    print(f"Configuración privada de Arti generada: {archivo}")


if __name__ == "__main__":
    main()
