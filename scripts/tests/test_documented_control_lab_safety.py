# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Regressioni offline sugli esempi pubblicati nei capitoli 18 e 19.

Sono controlli documentali, non sostituiscono un audit di sicurezza o
una verifica della rete Chutney. Non avviano Tor, Docker o servizi HTTP.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
CHAPTERS = ROOT / "source" / "it" / "capitoli"


def test_control_port_example_never_embeds_live_cookie():
    text = (CHAPTERS / "18-stem.tex").read_text(encoding="utf-8")
    assert r"AUTHENTICATE <COOKIE_HEX>" in text
    # Una sessione copiata in un libro NON deve contenere un cookie esadecimale
    # completo e apparentemente utilizzabile.
    assert not re.search(r"(?m)^> AUTHENTICATE [0-9a-fA-F]{64}\s*$", text)


def test_http_servers_only_share_a_sacrificial_directory():
    text = (CHAPTERS / "19-rete-privata.tex").read_text(encoding="utf-8")
    server_lines = [line for line in text.splitlines()
                    if "python3 -m http.server" in line and line.lstrip().startswith("$")]
    assert len(server_lines) == 2
    assert all('--bind 127.0.0.1 --directory "$WEBROOT"' in line
               for line in server_lines)
    assert 'WEBROOT=$(mktemp -d /tmp/torlibro-web.XXXXXX)' in text
    assert 'SERVER_HTTP_PID=$!' in text and 'SERVER_ONION_PID=$!' in text


def test_network_host_and_destroy_state_warnings_remain_visible():
    text = (CHAPTERS / "19-rete-privata.tex").read_text(encoding="utf-8")
    assert r"--network host" in text
    assert r"pulisci" in text and r"chiavi" in text
    assert r"non crea una barriera di isolamento" in text
