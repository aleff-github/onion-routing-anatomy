# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""I modelli di issue (.github/ISSUE_TEMPLATE/*.yml) rispettano la sintassi dei moduli di
GitHub, e il modello di pull request contiene le sezioni richieste. GitHub rifiuta in
silenzio un modulo non valido: lo si scoprirebbe solo dopo la pubblicazione."""
import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

RADICE = Path(__file__).resolve().parents[2]
MODELLI = RADICE / ".github" / "ISSUE_TEMPLATE"
TIPI = {"markdown", "input", "textarea", "dropdown", "checkboxes"}
ETICHETTE_AMMESSE = {"typo", "translation", "technical", "laboratory", "documentation",
                     "proposal", "status: to verify"}


def moduli():
    return sorted(p for p in MODELLI.glob("*.yml") if p.name != "config.yml")


def test_sei_moduli():
    nomi = [p.name for p in moduli()]
    assert nomi == ["01-typo.yml", "02-translation.yml", "03-technical-correction.yml",
                    "04-laboratory.yml", "05-documentation.yml", "06-proposal.yml"]


@pytest.mark.parametrize("percorso", moduli(), ids=lambda p: p.name)
def test_modulo_valido(percorso):
    m = yaml.safe_load(percorso.read_text(encoding="utf-8"))
    assert set(m) <= {"name", "description", "title", "labels", "assignees", "body",
                      "projects", "type"}
    assert m["name"].strip() and m["description"].strip()
    assert set(m.get("labels", [])) <= ETICHETTE_AMMESSE
    ids = set()
    campi = 0
    for elemento in m["body"]:
        assert elemento["type"] in TIPI
        attr = elemento["attributes"]
        if elemento["type"] == "markdown":
            assert attr["value"].strip()
            continue
        campi += 1
        assert re.fullmatch(r"[A-Za-z0-9_-]+", elemento["id"])
        assert elemento["id"] not in ids
        ids.add(elemento["id"])
        assert attr["label"].strip()
        if elemento["type"] == "dropdown":
            opzioni = attr["options"]
            assert opzioni and len(opzioni) == len(set(opzioni))
            assert all(isinstance(o, str) and o.strip() for o in opzioni)
        if elemento["type"] == "checkboxes":
            assert all(o["label"].strip() for o in attr["options"])
        assert set(elemento.get("validations", {})) <= {"required"}
    assert campi >= 2
    # Almeno un campo obbligatorio, perche' una segnalazione vuota non serve.
    assert any(e.get("validations", {}).get("required") for e in m["body"])


def test_config():
    c = yaml.safe_load((MODELLI / "config.yml").read_text(encoding="utf-8"))
    assert c["blank_issues_enabled"] is False
    for link in c["contact_links"]:
        assert link["name"] and link["about"] and link["url"].startswith("https://")
        m = re.match(r"https://github.com/aleff-github/onion-routing-anatomy/blob/main/(.+)",
                     link["url"])
        if m:
            assert (RADICE / m.group(1)).exists(), link["url"]


def test_modello_pull_request():
    testo = (RADICE / ".github" / "pull_request_template.md").read_text(encoding="utf-8")
    for sezione in ("Description", "Problem solved", "Language", "Chapter",
                    "Checks", "Other translations", "Rights"):
        assert sezione in testo, sezione
    assert "GPL-3.0-or-later" in testo
