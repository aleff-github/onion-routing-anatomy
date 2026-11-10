# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 7 — selezione del percorso.

Riferimenti: path-spec, "Path selection and constraints" e "Weighting node selection";
dir-spec, "banda-pesi". Implementa la scelta pesata di exit, guard e middle
con i vincoli principali (flag, relay distinti, stessa /16). Le famiglie, che richiedono
i microdescrittori, sono lasciate come esercizio.
Modulo didattico: la selezione reale di tor ha molte più regole (guard persistenti,
vanguards, isolamento degli stream, preferenze di porta).
"""
from __future__ import annotations

import ipaddress
import itertools
import math
import random
from dataclasses import dataclass

from .directory import Consenso, VoceRelay

POSIZIONI = ("guard", "middle", "exit")


def _controlla_posizione(posizione: str) -> None:
    if posizione not in POSIZIONI:
        raise ValueError("posizione relay sconosciuta")


def _controlla_scala(scale: int) -> None:
    if isinstance(scale, bool) or not isinstance(scale, int) or not 1 <= scale <= 2 ** 31 - 1:
        raise ValueError("parametro bwweightscale del consenso non valido")


def _tipo(r: VoceRelay) -> str:
    """g = solo Guard; e = solo Exit; d = Guard ed Exit; m = nessuno dei due."""
    # Come in tor (compute_weighted_bandwidths, node_select.c): un relay BadExit è pesato come non-exit.
    g, e = "Guard" in r.flag, "Exit" in r.flag and "BadExit" not in r.flag
    return {(True, True): "d", (True, False): "g", (False, True): "e", (False, False): "m"}[(g, e)]


def peso(r: VoceRelay, posizione: str, pesi: dict[str, int], scale: int = 10000) -> float:
    """Applica W<posizione><tipo> diviso per il parametro bwweightscale del consenso."""
    _controlla_posizione(posizione)
    _controlla_scala(scale)
    bw = r.banda if r.banda is not None else 0
    if isinstance(bw, bool) or not isinstance(bw, int) or bw < 0:
        raise ValueError("banda del relay non valida")
    factor = pesi.get(f"W{posizione[0]}{_tipo(r)}", scale)
    if isinstance(factor, bool) or not isinstance(factor, int) or not 0 <= factor <= scale:
        raise ValueError("peso di banda del consenso non valido")
    return bw * factor / scale

def idoneo(r: VoceRelay, posizione: str) -> bool:
    _controlla_posizione(posizione)
    if not {"Running", "Valid", "Fast"} <= r.flag:
        return False
    if posizione == "guard":
        return "Guard" in r.flag and "MiddleOnly" not in r.flag
    if posizione == "exit":
        return "Exit" in r.flag and "BadExit" not in r.flag and "MiddleOnly" not in r.flag
    return True


def rete16(r: VoceRelay) -> str:
    """Primi due ottetti di un indirizzo IPv4 valido (prefisso /16)."""
    try:
        ip = ipaddress.IPv4Address(r.ip)
    except (ipaddress.AddressValueError, TypeError) as exc:
        raise ValueError("indirizzo IPv4 del relay non valido") from exc
    return ".".join(str(ip).split(".")[:2])

class Selettore:
    """Pesi calcolati una sola volta per posizione; i vincoli si applicano per rifiuto.

    Come nel capitolo 13: si estrae un relay e, se viola un vincolo (stessa identità,
    stessa /16), si estrae di nuovo. Le somme cumulate dei pesi e le reti /16 dei
    candidati sono precalcolate, così ventimila percorsi richiedono pochi secondi.
    Se i tentativi si esauriscono, si estrae fra i soli candidati compatibili: un
    candidato ammissibile ma con peso molto basso non produce un falso fallimento.
    """

    def __init__(self, consenso: Consenso):
        self.scale = consenso.parametri.get("bwweightscale", 10000)
        _controlla_scala(self.scale)
        self.candidati, self.pesi, self.cumulati, self.reti = {}, {}, {}, {}
        for pos in POSIZIONI:
            candidati = [r for r in consenso.relay if idoneo(r, pos)]
            values = [peso(r, pos, consenso.pesi, self.scale) for r in candidati]
            self.candidati[pos] = [r for r, w in zip(candidati, values) if w > 0]
            self.pesi[pos] = [w for w in values if w > 0]
            self.cumulati[pos] = list(itertools.accumulate(self.pesi[pos]))
            self.reti[pos] = [rete16(r) for r in self.candidati[pos]]

    def scegli(self, pos: str, esclusi: list[VoceRelay], rng: random.Random,
               distinte_reti: bool = True, tentativi: int = 1000) -> VoceRelay:
        """Estrae per rifiuto; esauriti i tentativi, sceglie fra i soli relay compatibili."""
        _controlla_posizione(pos)
        if isinstance(tentativi, bool) or not isinstance(tentativi, int) or tentativi <= 0:
            raise ValueError("il numero di tentativi deve essere positivo")
        excluded_ids = {r.id_rsa for r in esclusi}
        excluded_nets = {rete16(r) for r in esclusi} if distinte_reti else set()
        candidati, reti = self.candidati[pos], self.reti[pos]
        if not candidati:
            raise LookupError(f"nessun relay idoneo per la posizione {pos}")
        indici = range(len(candidati))
        for _ in range(tentativi):
            i = rng.choices(indici, cum_weights=self.cumulati[pos])[0]
            if candidati[i].id_rsa not in excluded_ids and reti[i] not in excluded_nets:
                return candidati[i]
        pairs = [(r, w) for r, w, n in zip(candidati, self.pesi[pos], reti)
                 if r.id_rsa not in excluded_ids and n not in excluded_nets]
        if not pairs:
            raise LookupError(f"nessun relay idoneo per la posizione {pos}")
        return rng.choices([r for r, _ in pairs], weights=[w for _, w in pairs])[0]

    def percorso(self, rng: random.Random, guard: VoceRelay | None = None,
             distinte_reti: bool = True) -> tuple[VoceRelay, VoceRelay, VoceRelay]:
        """Prima l'Exit, poi un Guard valido (se fornito), infine il relay Middle."""
        if guard is not None:
            guard = next((r for r in self.candidati["guard"]
                          if r.id_rsa == guard.id_rsa), None)
            if guard is None:
                raise LookupError("il Guard fisso non è idoneo nel consenso")
        e = self.scegli("exit", [guard] if guard is not None else [], rng, distinte_reti)
        g = guard if guard is not None else self.scegli("guard", [e], rng, distinte_reti)
        m = self.scegli("middle", [e, g], rng, distinte_reti)
        return g, m, e

def probabilita(consenso: Consenso, posizione: str) -> dict[str, float]:
    """Probabilità pesate prima dei vincoli sulle reti e sulle policy di uscita."""
    _controlla_posizione(posizione)
    scale = consenso.parametri.get("bwweightscale", 10000)
    _controlla_scala(scale)
    pesi: dict[str, float] = {}
    for r in consenso.relay:
        if idoneo(r, posizione):
            w = peso(r, posizione, consenso.pesi, scale)
            if w > 0:
                nome = r.nome + ":" + r.id_rsa.hex()
                pesi[nome] = pesi.get(nome, 0.0) + w
    total = sum(pesi.values())
    return {nome: w / total for nome, w in pesi.items()} if total else {}

def quota_primi(prob: dict[str, float], n: int) -> float:
    """Quota delle n probabilità più elevate (zero se n è zero)."""
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise ValueError("n deve essere un intero non negativo")
    if any(isinstance(p, bool) or not isinstance(p, (float, int)) or
           not math.isfinite(p) or not 0 <= p <= 1 for p in prob.values()):
        raise ValueError("probabilità del relay non valida")
    return sum(sorted(prob.values(), reverse=True)[:n])

@dataclass
class Avversario:
    """Modello didattico a circuiti indipendenti, non gestione dei Guard persistenti."""
    quota_guard: float
    quota_exit: float

    def __post_init__(self) -> None:
        for fraction in (self.quota_guard, self.quota_exit):
            if isinstance(fraction, bool) or not isinstance(fraction, (int, float)) or not math.isfinite(fraction) or not 0 <= fraction <= 1:
                raise ValueError("le quote avversarie devono essere finite nell'intervallo [0,1]")

    def circuiti_compromessi(self, circuiti: int, guard_fisso: bool) -> float:
        """Probabilità di almeno un circuito con Guard e Exit dell'avversario."""
        if isinstance(circuiti, bool) or not isinstance(circuiti, int) or circuiti < 0:
            raise ValueError("il numero di circuiti deve essere un intero non negativo")
        fraction = self.quota_guard * self.quota_exit
        if not guard_fisso:
            return 1 - (1 - fraction) ** circuiti
        return self.quota_guard * (1 - (1 - self.quota_exit) ** circuiti)
