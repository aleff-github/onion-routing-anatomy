#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Rigenera i listati di output che non hanno bisogno della rete, e li confronta col libro.

I 53 controlli di ``make verifica-lab`` provano i *comportamenti*: che il circuito si
costruisca, che la firma sia valida, che il descrittore si decifri. Nessuno di essi
guardava i numeri **stampati** nei listati del libro, e infatti gli errori trovati in
revisione stavano quasi tutti lì: una dimensione di cella rimasta di un'esecuzione
precedente, un orario di consenso di venti secondi prima, un banner di versione vecchio.
Un listato non lo rilegge nessuno.

Questo controllo prende i listati che si possono rigenerare **senza rete**, perché i dati
stanno nel repository (il consenso e il descrittore conservati in
``labs/it/codice/torlab/test/dati/``) o si scaricano una volta sola (il consenso pubblico,
con ``make -C labs/it data``), riesegue il codice del libro e
verifica che ogni riga del listato compaia davvero nell'output. Le abbreviazioni con
``...`` sono ammesse: di quelle si controllano i pezzi, in ordine.

Restano fuori i listati che richiedono la rete viva: quelli li ricontrolla
``make verifica-lab``, e i loro valori per esecuzione (chiavi, impronte, orari) sono
dichiarati variabili nel cap. 19.

Uso: python3 scripts/verify_listings.py
"""
from __future__ import annotations

import random
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

RADICE = Path(__file__).resolve().parent.parent
CODICE = RADICE / "labs" / "it" / "codice"          # ambiente canonico dell'edizione italiana
DATI = CODICE / "torlab" / "test" / "dati"
_NOME_CONSENSO = "consensus-microdesc-2026-09-23-15"
# make -C labs/it data lo salva in labs/it/dati/collector; fonti/collector è il percorso storico.
CONSENSO_PUBBLICO = next((p for p in (RADICE / "labs" / "it" / "dati" / "collector" / _NOME_CONSENSO,
                                      RADICE / "fonti" / "collector" / _NOME_CONSENSO) if p.is_file()),
                         RADICE / "labs" / "it" / "dati" / "collector" / _NOME_CONSENSO)

sys.path.insert(0, str(CODICE))


# --- generatori: ognuno restituisce l'output atteso di un listato ---------------

def modulo(*argomenti: str) -> str:
    """Esegue `python3 -m torlab.<modulo> ...` come fa il listato del libro."""
    r = subprocess.run([sys.executable, "-m", *argomenti], cwd=CODICE,
                       capture_output=True, text=True, check=True)
    return r.stdout


def g_metriche() -> str:
    return modulo("torlab.metriche", str(CONSENSO_PUBBLICO))


def g_simulazione() -> str:
    return modulo("torlab.simulazione", str(CONSENSO_PUBBLICO), "0.05")


def g_percorsi() -> str:
    from torlab.directory import analizza_consenso
    from torlab.percorso import Selettore, _tipo, idoneo, probabilita, quota_primi
    c = analizza_consenso(CONSENSO_PUBBLICO.read_text())
    tot = sum(r.banda or 0 for r in c.relay)
    out = [f"relay: {len(c.relay)}"]
    bg = sum(r.banda or 0 for r in c.relay if "Guard" in r.flag) / tot
    be = sum(r.banda or 0 for r in c.relay if "Exit" in r.flag) / tot
    out.append(f"banda con Guard: {bg:.1%}    banda con Exit: {be:.1%}")
    for pos, et in (("guard", "guard "), ("middle", "middle"), ("exit", "exit  ")):
        p = probabilita(c, pos)
        out.append(f"{et}: idonei {sum(idoneo(r, pos) for r in c.relay):5d}; "
                   f"primi 10 = {quota_primi(p, 10):.1%}; primi 100 = {quota_primi(p, 100):.1%}")
    s, rng, cnt = Selettore(c), random.Random(7), Counter()
    for _ in range(20000):
        g, m, e = s.percorso(rng)
        cnt[_tipo(g) + _tipo(m) + _tipo(e)] += 1
    out.append("20000 percorsi: " + "  ".join(f"{k} {v / 20000:.1%}" for k, v in cnt.most_common()))
    return "\n".join(out)


def _consenso_conservato() -> str:
    return (DATI / "consenso-microdesc.txt").read_text()


def g_consenso_testo() -> str:
    """Gli estratti del cap. 12 sono righe letterali del consenso conservato."""
    return _consenso_conservato()


def g_consenso_analisi() -> str:
    from torlab.directory import analizza_certificati, analizza_consenso, verifica_consenso
    t = _consenso_conservato()
    c = analizza_consenso(t)
    cert = analizza_certificati((DATI / "certificati-autorita.txt").read_text())
    i = c.intestazione
    valide, richieste, _ = verifica_consenso(c, cert, 3)
    righe = [f"consenso: {len(t)} byte; {' '.join(i['valid-after'])} -> "
             f"{' '.join(i['valid-until'])}",
             f"metodo {i['consensus-method'][0]}; firme {len(c.firme)}; "
             f"certificati {len(cert)}",
             f"params: {c.parametri}"]
    for r in c.relay:
        righe.append(f"  {r.nome} {r.ip}:{r.orport} w={r.banda} flag={sorted(r.flag)}")
    righe.append(f"firme valide: {valide} (richieste: {richieste})")
    righe.append(f"microdescrittori: {len(c.relay)}")
    return "\n".join(righe)


def g_descrittore_onion() -> str:
    from torlab.onion import analizza_descrittore, chiave_accecata, chiave_da_indirizzo
    ind = (DATI / "descrittore-onion.indirizzo").read_text().strip()
    A = chiave_da_indirizzo(ind)
    d = analizza_descrittore((DATI / "descrittore-onion.txt").read_text(), A,
                             chiave_accecata(A, 3729540, 8))
    return (f"{ind}\nlifetime {d.durata_minuti} revisione {d.revisione} "
            f"punti di introduzione {len(d.punti_di_introduzione)}\n{d.strato_interno}")


# (descrizione, file, stringa che individua il listato, generatore, righe da saltare)
# L'ultimo campo è per le righe che richiedono la rete: vanno dichiarate qui, con il
# motivo, perché saltarle in silenzio significherebbe non controllare nulla.
CASI = [
    ("cap. 24, riassunto del consenso pubblico", "24-metrics.tex", "banda_totale:", g_metriche),
    ("cap. 29, simulazione dell'avversario", "29-ricerca.tex", "guard persistente", g_simulazione),
    ("cap. 13, la rete pubblica in numeri", "13-percorso.tex", "20000 percorsi", g_percorsi),
    # La riga `pr` del cap. 6 è quella dichiarata da 9357 dei 9358 relay del consenso.
    ("cap. 6, riga pr di un relay pubblico", "06-architettura.tex", "pr Conflux=1",
     lambda: CONSENSO_PUBBLICO.read_text()),
    ("cap. 12, intestazione del consenso", "12-directory.tex", "network-status-version", g_consenso_testo),
    ("cap. 12, voce di un relay", "12-directory.tex", "r test006e", g_consenso_testo),
    ("cap. 12, piè di pagina e firme", "12-directory.tex", "bandwidth-weights", g_consenso_testo),
    # I microdescrittori si scaricano dalla rete: la corrispondenza con le righe `m`
    # è provata dal controllo «Lab 6: microdescrittori = righe m» di make verifica-lab.
    ("cap. 12, risultati del laboratorio", "12-directory.tex", "firme valide:",
     g_consenso_analisi, r"corrispondono agli m"),
    ("cap. 14, descrittore dell'onion service", "14-onion-services.tex", "flow-control 1-2",
     g_descrittore_onion),
    ("cap. 14, indirizzo dell'esempio conservato", "14-onion-services.tex", ".onion",
     g_descrittore_onion),
]


def listato_con(testo: str, marcatore: str) -> list[str] | None:
    for m in re.finditer(r"\\begin\{lstlisting\}(?:\[[^\]]*\])?(.*?)\\end\{lstlisting\}",
                         testo, re.S):
        if marcatore in m.group(1):
            return [r for r in m.group(1).strip().splitlines() if r.strip()]
    return None


def normalizza(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def confronta(righe: list[str], atteso: str, salta: str | None = None) -> list[str]:
    """Ogni riga del listato deve comparire nell'output. `...` copre un pezzo omesso."""
    piatto = normalizza(atteso)
    problemi = []
    for r in righe:
        riga = normalizza(r)
        if riga.startswith("$") or riga.startswith("#"):
            continue                       # riga di comando, non output
        if salta and re.search(salta, riga):
            continue                       # riga che richiede la rete: la copre verifica-lab
        pezzi = [p for p in (x.strip() for x in riga.split("...")) if p]
        pos = 0
        for p in pezzi:
            i = piatto.find(p, pos)
            if i < 0:
                problemi.append(f"non trovato nell'output: «{p[:70]}»")
                break
            pos = i + len(p)
    return problemi


VARIABILI = {"VERSIONS", "CERTS", "AUTH_CHALLENGE", "AUTHENTICATE", "VPADDING"}

# Tolleranza sui punti della figura: i valori sono stampati con un decimale, e la
# simulazione è deterministica (seme fisso), quindi lo scarto ammesso è l'arrotondamento.
TOLLERANZA = 0.05


def figura_compromissione() -> list[str]:
    """Ogni punto tracciato nella figura del Laboratorio 19 deve venire dalla simulazione.

    La figura era stata aggiornata dopo la correzione del modello dei guard, ma un punto
    era rimasto indietro (giorno 175: 17,8 invece di 18,2). Un disegno non lo rilegge
    nessuno, e nessun controllo lo guardava.
    """
    from torlab.directory import analizza_consenso
    from torlab.simulazione import simula
    f = RADICE / "source" / "it" / "figure" / "fig29-compromissione.tex"
    curve = re.findall(r"plot coordinates \{([^}]+)\}", f.read_text())
    if len(curve) != 2:
        return [f"{f.name}: attese due curve, trovate {len(curve)}"]
    if not CONSENSO_PUBBLICO.is_file():
        print(f"[--] {f.name}: consenso pubblico assente, punti non verificati (make -C labs/it data)")
        return []
    c = analizza_consenso(CONSENSO_PUBBLICO.read_text())
    problemi = []
    # Nel file la prima curva è quella senza guard persistente (colore avviso).
    for testo, persistente, nome in ((curve[0], False, "guard per circuito"),
                                    (curve[1], True, "guard persistente")):
        r = simula(c, 0.05, 0.05, guard_persistente=persistente)
        for x, y in ((int(a), float(b)) for a, b in re.findall(r"\((\d+),([\d.]+)\)", testo)):
            vero = 100 * r.frazione_entro(x)
            # 1e-9: con 2000 client i valori sono multipli di 0,05 e un arrotondamento a un
            # decimale può distare esattamente TOLLERANZA (es. 12,75 -> 12,8).
            if abs(vero - y) > TOLLERANZA + 1e-9:
                problemi.append(f"{f.name}: curva «{nome}», giorno {x}: la figura traccia "
                                f"{y:.1f} ma la simulazione dà {vero:.1f}")
    return problemi


def coerenza_interna() -> list[str]:
    """Invarianti che un listato deve rispettare da solo, senza rieseguire nulla.

    Sono i controlli che avrebbero preso subito il difetto trovato in revisione: la
    scomposizione della cella CERTS era rimasta ai 581 byte di un'esecuzione
    precedente — sbagliati lì — mentre il totale stampato altrove non tornava.
    """
    problemi = []
    for cartella in ("capitoli", "appendici"):
        for f in sorted((RADICE / "source" / "it" / cartella).glob("*.tex")):
            testo = f.read_text()

            # 1. Una cella a lunghezza fissa ha sempre 509 byte di corpo.
            for m in re.finditer(r"([A-Z][A-Z0-9_]+) corpo=(\d+) byte", testo):
                comando, n = m.group(1), int(m.group(2))
                if comando not in VARIABILI and n != 509:
                    riga = testo.count("\n", 0, m.start()) + 1
                    problemi.append(f"{f.name}:{riga}: {comando} è una cella fissa, "
                                    f"il corpo deve essere 509 byte, non {n}")

            # 2. Il corpo di una CERTS vale 1 byte di conteggio più 3 byte di
            #    intestazione per certificato: se il capitolo scompone i certificati,
            #    la somma deve dare il totale che dichiara.
            pezzi = [int(x) for x in re.findall(r"^\s*tipo \d+\s+(\d+) byte", testo, re.M)]
            totali = {int(x) for x in re.findall(r"CERTS[^\n]{0,12}?(\d{3,5}) byte", testo)}
            if pezzi and totali:
                atteso = 1 + sum(3 + p for p in pezzi)
                if atteso not in totali:
                    problemi.append(f"{f.name}: i certificati elencati sommano a {atteso} byte "
                                    f"(1 + 3 per certificato + i corpi), ma il capitolo "
                                    f"dichiara una CERTS di {sorted(totali)} byte")
    return problemi


# Generatori che leggono il consenso pubblico: senza il file il listato non si può rigenerare.
_SERVE_CONSENSO = {g_metriche, g_simulazione, g_percorsi}


def main() -> None:
    problemi = 0
    saltati = 0
    for p in coerenza_interna() + figura_compromissione():
        print(f"[!] {p}")
        problemi += 1
    for descrizione, nome, marcatore, genera, *resto in CASI:
        salta = resto[0] if resto else None
        if not CONSENSO_PUBBLICO.is_file() and (genera in _SERVE_CONSENSO or "riga pr" in descrizione):
            print(f"[--] {descrizione}: consenso pubblico assente, listato non verificato")
            saltati += 1
            continue
        for cartella in ("capitoli", "appendici"):
            f = RADICE / "source" / "it" / cartella / nome
            if f.is_file():
                break
        righe = listato_con(f.read_text(), marcatore)
        if righe is None:
            print(f"[!] {descrizione}: nessun listato contiene «{marcatore}» in {nome}")
            problemi += 1
            continue
        for p in confronta(righe, genera(), salta):
            print(f"[!] {descrizione} ({nome}): {p}")
            problemi += 1
    punti = sum(len(re.findall(r"\(\d+,[\d.]+\)", c)) for c in re.findall(
        r"plot coordinates \{([^}]+)\}",
        (RADICE / "source" / "it" / "figure" / "fig29-compromissione.tex").read_text()))
    if saltati:
        print(f"\n{len(CASI) - saltati} listati su {len(CASI)} rigenerati senza rete; {saltati} saltati "
              f"e {punti} punti di figura non verificati perché manca il consenso pubblico "
              f"(make -C labs/it data).")
    else:
        print(f"\n{len(CASI)} listati e {punti} punti di figura rigenerati senza rete.")
    if problemi:
        print(f"{problemi} righe non corrispondono all'output del codice.")
        sys.exit(1)
    print("Tutti i listati corrispondono a ciò che il codice produce oggi.")


if __name__ == "__main__":
    main()
