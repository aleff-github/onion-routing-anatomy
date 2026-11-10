#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Regressione statica: i laboratori non devono aggirare SOCKS per NO_PROXY.

Non esegue richieste di rete e non certifica la corretta esecuzione Tor.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
# Percorsi localizzati di ogni edizione: guida del laboratorio 10, guida del
# laboratorio 20 e script della scoperta ristretta.
EDITIONS = {
    "en": ("lab", "wiki/Laboratory-10-Bridge.md", "wiki/Laboratory-20-Arti.md",
           "restricted_discovery.py"),
    "es": ("laboratorio", "wiki/Laboratorio-10-Puente.md", "wiki/Laboratorio-20-Arti.md",
           "descubrimiento_restringido.py"),
    "ru": ("лаборатория", "вики/Лабораторная-10-Мост.md", "вики/Лабораторная-20-Arti.md",
           "restricted_discovery.py"),
    "zh-Hans": ("实验室", "维基/实验-10-网桥.md", "维基/实验-20-Arti.md",
                "restricted_discovery.py"),
}
bad: list[str] = []

for locale, (lab, guide10, guide20, discovery) in EDITIONS.items():
    paths = [
        ROOT / "labs" / locale / guide10,
        ROOT / "labs" / locale / guide20,
        ROOT / "labs" / locale / lab / discovery,
    ]
    if locale == "es":
        paths.extend([
            ROOT / "labs/es/laboratorio/puente_obfs4.py",
            ROOT / "labs/es/laboratorio/fuga_dns.py",
        ])

    for path in paths:
        name = str(path.relative_to(ROOT))
        if not path.is_file():
            bad.append(f"{name}: sorgente mancante")
            continue
        source = path.read_text(encoding="utf-8")
        if "--socks5" not in source:
            bad.append(f"{name}: manca una richiesta con SOCKS")
            continue
        required = (
            r'"--noproxy"\s*,\s*""' if path.suffix == ".py"
            else r'--noproxy\s+""'
        )
        if not re.search(required, source):
            bad.append(f"{name}: manca il reset esplicito di NO_PROXY")

if bad:
    for problem in bad:
        print("FAIL", problem)
    sys.exit(1)
print("PASS: 14 richieste/example SOCKS protette dal bypass NO_PROXY (scansione statica).")
