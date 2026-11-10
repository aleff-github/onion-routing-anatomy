# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratorio 19 — tempo alla prima compromissione in un modello TorPS semplificato.

Un avversario controlla quote fisse della banda pesata di Guard ed Exit.
Ciascun client simulato crea un numero fisso di circuiti al giorno:
conserva un Guard per una durata didattica oppure lo cambia a ogni circuito.
La compromissione avviene quando un circuito contiene Guard ed Exit avversari.
Non sono modellati relay intermedi, campionamento e priorità dei Guard,
guasti, famiglie, IPv6 o dipendenze tra percorsi.

guard-spec prevede per impostazione predefinita 120 giorni per i Guard non
confermati e 60 per quelli confermati, ma il protocollo gestisce campioni e
date di conferma con ulteriori regole. Il nostro intervallo 48–60 giorni
è SOLO un'approssimazione didattica, non la durata esatta di un Guard reale
né una previsione di deanonimizzazione.
"""
from __future__ import annotations

import bisect
import itertools
import math
import random
from dataclasses import dataclass
from pathlib import Path

from .directory import Consenso
from .percorso import idoneo, peso

GUARD_LIFETIME = 120                  # Durata ordinaria Guard non confermato (giorni)
GUARD_CONFIRMED_MIN_LIFETIME = 60     # Durata minima Guard confermato (giorni)
BACKDATE = GUARD_LIFETIME // 10       # Massima retrodatazione del modello didattico


def _positive_int(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} deve essere un intero positivo")


def _durata_guard(rng: random.Random, lifetime: int) -> int:
    """Durata approssimata del Guard; la retrodatazione lascia un valore positivo."""
    if isinstance(lifetime, bool) or not isinstance(lifetime, int) or lifetime < 1:
        raise ValueError("la durata del Guard deve essere un intero positivo")
    return lifetime - rng.randint(0, min(BACKDATE, lifetime - 1))


class Urna:
    """Estrazione pesata con quote avversarie e pesi verificati."""

    def __init__(self, pesi: list[float], quota_avversario: float):
        if isinstance(quota_avversario, bool) or not isinstance(quota_avversario, (int, float)) or not math.isfinite(quota_avversario) or not 0 <= quota_avversario <= 1:
            raise ValueError("la quota avversaria deve essere finita e compresa fra 0 e 1")
        if any(isinstance(w, bool) or not isinstance(w, (int, float)) or not math.isfinite(w) or w < 0 for w in pesi):
            raise ValueError("i pesi devono essere numeri non negativi e finiti")
        self.n = len(pesi)
        self.all_adversarial = quota_avversario == 1
        if self.all_adversarial:
            self.cumulati = []
            return
        max_weight = max(pesi, default=0.0)
        if max_weight <= 0:
            raise ValueError("serve almeno un relay onesto con peso positivo")
        scaled = [w / max_weight for w in pesi]
        total = math.fsum(scaled)
        if not math.isfinite(total) or total <= 0:
            raise ValueError("serve almeno un relay onesto con peso positivo")
        honest = 1.0 - quota_avversario
        # Normalizza prima rispetto al peso massimo per evitare overflow float.
        normalized = [w / total * honest for w in scaled]
        self.cumulati = list(itertools.accumulate(normalized + [quota_avversario]))

    def ostile(self, rng: random.Random) -> bool:
        """Indica se il campione estratto appartiene all'avversario."""
        if self.all_adversarial:
            return True
        x = rng.random() * self.cumulati[-1]
        return bisect.bisect_right(self.cumulati, x) >= self.n


@dataclass
class Risultato:
    """Primo giorno di compromissione per client; None indica censura."""
    giorni_compromissione: list[int | None]

    def frazione_entro(self, day: int) -> float:
        """Frazione di client compromessi entro il giorno richiesto."""
        if isinstance(day, bool) or not isinstance(day, int) or day < 0:
            raise ValueError("il giorno deve essere un intero non negativo")
        if not self.giorni_compromissione:
            raise ValueError("nessun client nel risultato della simulazione")
        return sum(1 for d in self.giorni_compromissione if d is not None and d <= day) / len(self.giorni_compromissione)

    def mediana(self) -> int | None:
        """Primo giorno in cui almeno metà dei client risulta compromessa."""
        if not self.giorni_compromissione:
            return None
        compromised = sorted(d for d in self.giorni_compromissione if d is not None)
        needed = (len(self.giorni_compromissione) + 1) // 2
        return compromised[needed - 1] if len(compromised) >= needed else None


def simula(consenso: Consenso, quota_guard: float, quota_exit: float, *, client: int = 2000,
           giorni: int = 180, circuiti: int = 20, guard_persistente: bool = True,
           vita_guard: int = GUARD_CONFIRMED_MIN_LIFETIME, seme: int = 1) -> Risultato:
    """Esempio Monte Carlo, non una previsione dell'anonimato reale."""
    for label, value in (("client", client), ("giorni", giorni),
                         ("circuiti", circuiti), ("vita_guard", vita_guard)):
        _positive_int(value, label)
    scale = consenso.parametri.get("bwweightscale", 10000)
    rng = random.Random(seme)
    guard_weights = [peso(r, "guard", consenso.pesi, scale) for r in consenso.relay if idoneo(r, "guard")]
    exit_weights = [peso(r, "exit", consenso.pesi, scale) for r in consenso.relay if idoneo(r, "exit")]
    guard = Urna(guard_weights, quota_guard)
    exit_ = Urna(exit_weights, quota_exit)
    results: list[int | None] = []
    for _ in range(client):
        compromised = None
        if guard_persistente:
            guard_adversarial = guard.ostile(rng)
            expiration = _durata_guard(rng, vita_guard)
        for day in range(1, giorni + 1):
            if guard_persistente and day > expiration:
                guard_adversarial = guard.ostile(rng)
                expiration = day + _durata_guard(rng, vita_guard) - 1
            for _ in range(circuiti):
                g = guard_adversarial if guard_persistente else guard.ostile(rng)
                if g and exit_.ostile(rng):
                    compromised = day
                    break
            if compromised is not None:
                break
        results.append(compromised)
    return Risultato(results)


if __name__ == "__main__":
    import sys
    from .directory import analizza_consenso

    if len(sys.argv) < 2:
        raise SystemExit("Uso: python -m torlab.simulazione FILE_CONSENSO [QUOTA_AVVERSARIO]")
    path = Path(sys.argv[1])
    c = analizza_consenso(path.read_text(encoding="utf-8"))
    q = float(sys.argv[2]) if len(sys.argv) > 2 else 0.01
    print(f"avversario: {q:.0%} della banda di guard e {q:.0%} della banda di exit; 2000 client, 180 giorni, 20 circuiti/giorno")
    for persistent in (True, False):
        result = simula(c, q, q, guard_persistente=persistent)
        summary = "  ".join(f"{d:>3}g: {result.frazione_entro(d):5.1%}" for d in (1, 7, 30, 90, 180))
        label = ("guard persistente" if persistent else "guard per circuito")
        print(f"{label:19s} {summary}  mediana: {result.mediana()}")
