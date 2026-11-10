# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Laboratorio 17 (capitolo 27): il limite di otto celle RELAY_EARLY precede il 2014; il fix del 2014 blocca quelle dirette al client.
# Un circuito di un salto verso 004r; inviamo N celle RELAY_EARLY con un messaggio DROP
# (che il relay scarta in silenzio) e poi chiediamo una connessione di directory per vedere
# se il circuito è ancora vivo.
import sys
from torlab.celle import Cella, Comando, ComandoRelay, MessaggioRelay
from torlab.circuito import Circuito, ErroreCircuito, costruisci
from torlab.laboratorio import relay


def prova(n: int) -> str:
    """Prova intenzionalmente fuori specifica; solo nodo 004r privato."""
    if n not in (8, 9):
        raise ValueError("Sono ammessi solo 8 o 9 celle RELAY_EARLY.")
    circ = costruisci([relay("004r")], cc=False)
    try:
        for _ in range(n):
            # RELAY_EARLY + DROP non è conforme alle prescrizioni dei client Tor.
            corpo = circ.cripto.cifra(MessaggioRelay(ComandoRelay.DROP, 0), None)
            circ.canale.invia(Cella(circ.circ_id, Comando.RELAY_EARLY, corpo))
        circ.invia(MessaggioRelay(ComandoRelay.BEGIN_DIR, 1))
        _, risposta = circ.ricevi()
        return ComandoRelay(risposta.comando).name
    except ErroreCircuito as exc:
        return str(exc)
    finally:
        circ.canale.sock.close()


def main() -> int:
    valori = list(map(int, sys.argv[1:])) if len(sys.argv) > 1 else [8, 9]
    if not valori or any(n not in (8, 9) for n in valori) or len(valori) != len(set(valori)):
        raise SystemExit("Sono ammessi solo 8 o 9 celle RELAY_EARLY.")
    risultati = {}
    for n in valori:
        risultati[n] = prova(n)
        print(f"{n} celle RELAY_EARLY -> {risultati[n]}")
    # Controllo didattico della sola osservazione storica, non regola normativa.
    return 0 if all(risultati[n] == ("CONNECTED" if n == 8 else "circuito distrutto, motivo 1") for n in valori) else 1

if __name__ == "__main__":
    raise SystemExit(main())
