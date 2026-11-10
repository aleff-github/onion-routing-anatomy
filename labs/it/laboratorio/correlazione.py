# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
# Laboratorio 16 (capitolo 26): correlazione da estremo a estremo, solo sul nostro traffico.
# N client inviano dati attraverso la rete privata con ritmi casuali diversi; un "osservatore
# d'ingresso" registra quando ogni client scrive, un "osservatore d'uscita" (il server) quando
# i byte arrivano. Confrontando le due serie temporali si ricostruisce chi parla con chi.
import random, socket, socketserver, statistics, struct, sys, threading, time

N, DURATA, BIN, BLOCCO = 6, 20.0, 0.25, 2048
PORTA_SERVER, SOCKS = 8095, ("127.0.0.1", 9008)
arrivi: dict[int, list[tuple[float, int]]] = {}
invii: dict[int, list[tuple[float, int]]] = {}
verita: dict[int, int] = {}                       # usata solo per valutare, mai per abbinare


class Ricevitore(socketserver.BaseRequestHandler):
    def handle(self):
        registro = []
        prima = self.request.recv(4, socket.MSG_WAITALL)
        chiave = len(arrivi)                         # l'osservatore d'uscita numera i flussi a caso
        verita[chiave] = struct.unpack(">I", prima)[0]
        arrivi[chiave] = registro
        while True:
            dati = self.request.recv(65536)
            if not dati:
                break
            registro.append((time.time(), len(dati)))


def socks5(credenziali: str) -> socket.socket:
    s = socket.create_connection(SOCKS)
    s.sendall(b"\x05\x01\x02")
    assert s.recv(2) == b"\x05\x02"
    u = credenziali.encode()
    s.sendall(b"\x01" + bytes([len(u)]) + u + b"\x01x")
    assert s.recv(2)[1] == 0
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack(">H", PORTA_SERVER))
    risposta = s.recv(10)
    assert risposta[1] == 0, f"SOCKS: errore {risposta[1]}"
    return s


def client(i: int, rng: random.Random, inizio: float):
    s = socks5(f"flusso-{i}")                        # credenziali SOCKS diverse: circuiti distinti non garantiti
    s.sendall(struct.pack(">I", i))
    registro = invii[i] = []
    while time.time() - inizio < DURATA:
        if rng.random() < 0.5:                       # periodo attivo: una raffica di blocchi
            for _ in range(rng.randint(5, 40)):
                s.sendall(b"\0" * BLOCCO)
                registro.append((time.time(), BLOCCO))
        time.sleep(rng.uniform(0.2, 1.0))            # silenzio
    s.close()


def serie(eventi, inizio):
    v = [0] * int(DURATA / BIN + 20)
    for t, n in eventi:
        if t < inizio:                   # int() tronca verso zero: -0,01 finirebbe nell'intervallo 0
            continue
        k = int((t - inizio) / BIN)
        if 0 <= k < len(v):
            v[k] += n
    return v


def main():
    seme = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    server = socketserver.ThreadingTCPServer(("127.0.0.1", PORTA_SERVER), Ricevitore)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    inizio = time.time()
    fili = [threading.Thread(target=client, args=(i, random.Random(seme * 100 + i), inizio)) for i in range(N)]
    for f in fili:
        f.start()
    for f in fili:
        f.join()
    time.sleep(3)
    server.shutdown()
    ingresso = {i: serie(e, inizio) for i, e in invii.items()}
    uscita = {k: serie(e, inizio) for k, e in arrivi.items()}
    corretti = 0
    for i, a in ingresso.items():
        punteggi = {k: statistics.correlation(a, b) for k, b in uscita.items()}
        migliore = max(punteggi, key=punteggi.get)
        ok = verita[migliore] == i
        corretti += ok
        riga = " ".join(f"{punteggi[k]:+.2f}" for k in sorted(uscita))
        print(f"client {i}: {riga}  -> uscita {migliore} {'OK' if ok else 'ERRATO'}")
    print(f"abbinamenti corretti: {corretti}/{len(ingresso)}")


if __name__ == "__main__":
    main()
