# Laboratorio 12 — Le celle dentro il TLS

| | |
|---|---|
| **Capitolo** | 20 — Analizzare il traffico di Tor |
| **Serve la rete?** | sì |
| **Prerequisiti** | Laboratori 1–4 |
| **Tempo** | 1–2 ore |
| **File** | `labs/it/codice/torlab/traffico.py` |

## Che cosa dimostra

Che cosa c'è davvero dentro una connessione Tor, guardandola dall'esterno **con le
chiavi in mano**. Catturiamo il nostro traffico con `tcpdump`, esportiamo le chiavi di
sessione TLS del nostro client (`SSLKEYLOGFILE`), e facciamo decifrare la cattura a
`tshark`: dentro compaiono le celle, una per una, nell'ordine dell'handshake.

È l'unico modo onesto di fare quest'esperimento: si decifra **il proprio** traffico,
usando chiavi che il proprio programma esporta di sua volontà. Non c'è niente da
attaccare.

## Preparazione

```bash
make -C labs/it/laboratorio avvia
export PYTHONPATH=labs/it/codice
```

## Esecuzione

```bash
python3 - <<'EOF'
import os, subprocess, time
from torlab.celle import Comando as C, ErroreCella
from torlab.circuito import costruisci
from torlab.laboratorio import relay, NODI
from torlab.traffico import celle_da_follow

os.umask(0o077)  # nuovi file di segreti leggibili solo da questo utente
chiavi = NODI.parent / "chiavi.log"
if chiavi.exists():
    raise FileExistsError("Chiavi TLS gia' presenti: salvarle e cancellarle esplicitamente prima di ripetere")

# 1. la cattura: solo la porta del relay 004r
subprocess.run(["docker", "exec", "-u", "0", "-d", "torlibro-rete", "sh", "-c",
                "timeout 12 tcpdump -i lo -w /lab/net/cattura.pcap 'tcp port 5104'"])
time.sleep(2)

# 2. il traffico, con l'esportazione delle chiavi TLS
os.environ["SSLKEYLOGFILE"] = str(chiavi)
try:
    costruisci([relay("004r")], cc=False)
finally:
    del os.environ["SSLKEYLOGFILE"]
time.sleep(11)
print("chiavi TLS esportate:", len(chiavi.read_text().splitlines()), "righe")

# 3. la decifratura, e le celle
for i in range(8):
    out = subprocess.run(["docker", "exec", "torlibro-rete", "tshark",
                          "-r", "/lab/net/cattura.pcap",
                          "-o", "tls.keylog_file:/lab/net/chiavi.log",
                          "-q", "-z", f"follow,tls,raw,{i}"],
                         capture_output=True, text=True).stdout
    try:
        celle = celle_da_follow(out)
    except (ErroreCella, ValueError):
        continue  # altri stream o catture incomplete non vanno interpretati
    if celle:
        print(f"flusso {i}:")
        for verso, cella, versione in celle:
            print(f"   {verso} {C(cella.comando).name} (corpo {len(cella.corpo)} byte)")
        break
EOF
```

Il file `chiavi.log` contiene segreti TLS e può permettere di decifrare
il traffico della sessione. Il programma ne rifiuta la sovrascrittura:
una eventuale copia precedente va salvata o eliminata deliberatamente.
Al termine elimina i file `chiavi.log` e `cattura.pcap` soltanto
dopo aver chiuso l'analisi e aver verificato che non siano dati da
conservare. La funzione `celle_da_follow` richiede il VERSIONS
di entrambi i peer e calcola la versione comune, anziché presumere
che sia sempre 5.

## Output atteso

```
chiavi TLS esportate: 6 righe
flusso 1:
   client VERSIONS (corpo 4 byte)
   relay VERSIONS (corpo 6 byte)
   relay CERTS (corpo 1446 byte)
   relay AUTH_CHALLENGE (corpo 36 byte)
   relay NETINFO (corpo 509 byte)
   client NETINFO (corpo 509 byte)
   client CREATE2 (corpo 509 byte)
   relay CREATED2 (corpo 509 byte)
```

Come leggerlo:

- È l'handshake del [Laboratorio 1](Laboratorio-01-Canale.md), visto dall'altra parte: le
  stesse celle, nello stesso ordine, ma stavolta estratte dai byte sul filo.
- Il numero del flusso TLS non è prevedibile (sul loopback c'è anche altro traffico),
  perciò il ciclo ne prova otto e si ferma al primo che contiene celle.
- Le `NETINFO`, `CREATE2` e `CREATED2` hanno tutte un corpo di **509 byte**: è
  l'uniformità delle celle a lunghezza fissa. Chi guarda da fuori, senza chiavi, non
  distingue una `CREATE2` da una `NETINFO`.
- Le chiavi esportate sono 6 righe: `SSLKEYLOGFILE` scrive più segreti per sessione
  (handshake e traffico, nelle due direzioni).

## Che cosa si vede *senza* le chiavi

Questa è la domanda vera del capitolo 20, e la risposta è: molto poco. Un osservatore
vede una connessione TLS 1.3 verso un indirizzo che sta nel consenso pubblico, e la
dimensione e il ritmo dei pacchetti. Non vede le celle, non vede i CircID, non sa quanti
circuiti passano su quel canale. Ma le dimensioni e i tempi bastano per la correlazione
da estremo a estremo: è il [Laboratorio 16](Laboratorio-16-Correlazione.md).

## Verifica automatica

Il controllo `lab12` verifica che la sequenza estratta cominci con due `VERSIONS` e
contenga una `CREATED2`.

## Problemi noti

| Sintomo | Causa |
|---|---|
| Nessuna cella in nessun flusso | il file delle chiavi è vuoto: `SSLKEYLOGFILE` dev'essere nell'ambiente **prima** che il socket TLS venga creato |
| `tshark` non apre il pcap | la cattura richiede i privilegi di root nel container: l'opzione `-u 0` di `docker exec` |
| Il pcap è vuoto | `tcpdump` è partito dopo il traffico: due secondi di attesa |
| Celle decifrate a metà | la cattura si è chiusa mentre il canale era ancora attivo: allunga il `timeout` |
