# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""scripts/verify_labs.py punta all'ambiente italiano che esiste davvero (labs/it/codice,
laboratorio, dati) e la sua parte senza rete gira. Il libro rimanda il lettore a questo script:
se un cambio di struttura ne rompe i percorsi, lo si deve scoprire qui e non a una nuova
versione di tor."""
import subprocess
import sys
from pathlib import Path

RADICE = Path(__file__).resolve().parents[2]
SCRIPT = RADICE / "scripts" / "verify_labs.py"


def test_percorsi_esistenti():
    spazio = {"__file__": str(SCRIPT)}
    testa = SCRIPT.read_text(encoding="utf-8").split("sys.path.insert", 1)[0]
    exec(compile(testa, str(SCRIPT), "exec"), spazio)
    for nome in ("CODICE", "LAB"):
        assert spazio[nome].is_dir(), f"{nome} = {spazio[nome]} non esiste"
    assert spazio["DATI"].parent.is_dir(), f"DATI = {spazio['DATI']}: manca la cartella madre"


def test_solo_offline():
    esito = subprocess.run([sys.executable, str(SCRIPT), "--solo-offline"], cwd=RADICE,
                           capture_output=True, text=True, timeout=300)
    assert esito.returncode == 0, esito.stdout + esito.stderr
    assert "controlli superati" in esito.stdout
