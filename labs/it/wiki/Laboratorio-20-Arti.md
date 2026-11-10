# Laboratorio 20 — Arti nella rete privata

| | |
|---|---|
| **Capitolo** | 30 — Arti, la riscrittura in Rust |
| **Serve la rete?** | sì, più Rust per compilare Arti |
| **Prerequisiti** | la rete avviata; `cargo` |
| **Tempo** | 1 ora, più il tempo di compilazione |
| **File** | `labs/it/laboratorio/arti_config.py` |

## Che cosa dimostra

Che la rete privata del libro non è «la rete di `tor`»: è una rete Tor, e un'altra
implementazione del protocollo vi si collega senza che nulla cambi. Arti fa il bootstrap,
apre circuiti e fa uscire il traffico dagli stessi exit, parlando con relay scritti in C.

È anche la prova migliore che i formati studiati nei capitoli precedenti sono davvero
interoperabili e non «quello che fa tor».

## Preparazione

Compilare Arti 2.6.0 (**versione storica fissata per riprodurre il capitolo**; tempi e spazio dipendono dalla macchina). Non usare questo binario storico come scelta consigliata per collegamenti alla rete Tor pubblica: le release successive includono correzioni di sicurezza (per esempio Arti 2.7.0, ottobre 2026). La prova descritta riguarda esclusivamente la topologia locale isolata:

```bash
mkdir -p labs/it/vendor
git clone https://gitlab.torproject.org/tpo/core/arti.git labs/it/vendor/arti
git -C labs/it/vendor/arti checkout arti-v2.6.0
(cd labs/it/vendor/arti && cargo build --release -p arti --locked)
```

Generare la configurazione per la rete privata:

```bash
python3 labs/it/laboratorio/arti_config.py
```

Lo script legge identità e porte delle tre autorità dai file dei nodi e scrive
`labs/it/laboratorio/net/arti/arti.toml`, con le stesse scelte che fa Chutney: autorità e fallback della
rete privata, indirizzi locali ammessi, nessun vincolo di sottorete (tutti i nodi sono
su 127.0.0.1) e `hsdir_interval` accorciato.

## Esecuzione

Dalla radice del repository, eseguire i comandi seguenti in una shell POSIX. La rete privata deve essere già avviata con `make -C labs/it/laboratorio avvia` (non eseguire nuovamente il comando se è già in funzione). Il controllo verifica **sia** il codice HTTP **sia** il corpo di risposta del server, così un eventuale altro servizio sulla porta 8080 non può essere scambiato per quello del laboratorio. Usa un gestore HTTP fisso, senza pubblicare la directory corrente.

```sh
(
set -eu
ARTI_BIN="labs/it/vendor/arti/target/release/arti"
ARTI_CFG="labs/it/laboratorio/net/arti/arti.toml"
ARTI_LOG="labs/it/laboratorio/net/arti/arti.log"
HTTP_LOG="labs/it/laboratorio/net/arti/http.log"
ARTI_PID=
HTTP_PID=
BODY_FILE=

cleanup() {
  if [ -n "$HTTP_PID" ]; then
    kill "$HTTP_PID" 2>/dev/null || true
    wait "$HTTP_PID" 2>/dev/null || true
  fi
  if [ -n "$ARTI_PID" ]; then
    kill "$ARTI_PID" 2>/dev/null || true
    wait "$ARTI_PID" 2>/dev/null || true
  fi
  if [ -n "$BODY_FILE" ]; then rm -f "$BODY_FILE"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

[ -x "$ARTI_BIN" ] && [ -f "$ARTI_CFG" ] || {
  echo "Binario Arti o configurazione privata mancanti" >&2
  exit 1
}
: > "$ARTI_LOG"
"$ARTI_BIN" proxy -c "$ARTI_CFG" > "$ARTI_LOG" 2>&1 &
ARTI_PID=$!

# Attendere il bootstrap di questa istanza Arti
ready=0
n=0
while [ "$n" -lt 60 ]; do
  if grep -q "proxy now functional" "$ARTI_LOG" && kill -0 "$ARTI_PID" 2>/dev/null; then
    ready=1
    break
  fi
  if ! kill -0 "$ARTI_PID" 2>/dev/null; then
    echo "Arti terminato prima del bootstrap; controlla $ARTI_LOG" >&2
    exit 1
  fi
  n=$((n + 1))
  sleep 2
done
[ "$ready" -eq 1 ] || {
  echo "Bootstrap Arti incompleto; controlla $ARTI_LOG" >&2
  exit 1
}

# Server HTTP locale: risposta fissa solo su /
python3 -u - > "$HTTP_LOG" 2>&1 <<'PY' &
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        body = b"arti-private-lab-ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass

ThreadingHTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
PY
HTTP_PID=$!
sleep 1
kill -0 "$HTTP_PID" 2>/dev/null || {
  echo "Server HTTP locale non avviato; controlla $HTTP_LOG" >&2
  exit 1
}

BODY_FILE=$(mktemp)
HTTP_CODE=$(curl --fail --silent --show-error --max-time 30 \
  --noproxy "" --socks5-hostname 127.0.0.1:9150 \
  -o "$BODY_FILE" -w '%{http_code}' http://127.0.0.1:8080/)
[ "$HTTP_CODE" = "200" ] && [ "$(cat "$BODY_FILE")" = "arti-private-lab-ok" ] || {
  echo "Risposta HTTP inattesa dal laboratorio privato" >&2
  exit 1
}
printf '%s\n' "$HTTP_CODE"
)
```

La procedura tronca il log precedente, controlla che il processo Arti rimanga in vita, fallisce se la porta 8080 è già occupata e chiude **solo i processi che ha avviato** anche in caso di errore o interruzione gestita. Non usare `pkill` per arrestare istanze non correlate. Il codice `200` conferma il successo HTTP **soltanto insieme** alla risposta fissa `arti-private-lab-ok` e al codice d'uscita zero di `curl`. La prova presuppone che il server locale sia raggiungibile tramite gli exit della **rete privata**, non attraverso la rete Tor pubblica.

## Output storico di riferimento

```
2026-09-24T16:05:45Z  INFO arti::subcommands::proxy: Sufficiently bootstrapped; proxy now functional.
200
```

Come leggerlo:

- Arti ha scaricato il consenso dalle autorità della rete privata, ne ha verificato le
  firme, ha costruito un circuito e ha fatto uscire una richiesta HTTP. Nessun relay
  della rete sa di star parlando con un'implementazione diversa, e non gli serve saperlo.
- `--noproxy ""` forza il passaggio da SOCKS anche per `127.0.0.1`, evitando le esclusioni ambientali `NO_PROXY`/`no_proxy`. L'output sopra è un esempio precedente, **non** una nuova esecuzione.
- La porta SOCKS predefinita di Arti è la **9150** (quella di Tor Browser), non la 9050.

## Che cosa cambia rispetto a tor

La configurazione è TOML invece del formato `torrc`, e l'elenco delle autorità va scritto
con `rsa_identity`, `ed_identity` e `orports` — cioè con **entrambe** le identità,
mentre il `torrc` di tor si accontenta dell'impronta RSA.

Il capitolo 30 entra nel merito di che cosa Arti fa già, che cosa non fa ancora (il ruolo
di relay, per esempio) e perché una riscrittura in Rust valga la fatica.

Una nota che è costata una correzione al libro: la numerazione dei sottoprotocolli in
`Compatibility.md` di Arti è **sfasata di uno** rispetto a torspec per `FlowCtrl`. La
specifica e il consenso reale (`FlowCtrl=1-2`) dicono 1 = `AUTH_SENDME`, 2 = controllo
della congestione. Quando due fonti non concordano, vince la specifica — e il consenso
pubblico è l'arbitro.

## Verifica automatica

Il verificatore italiano `scripts/verify_labs.py::lab20` usa lo stesso ambiente di questa guida: il binario `labs/it/vendor/arti/target/release/arti` (in subordine il percorso storico `fonti/arti/...`), il generatore `labs/it/laboratorio/arti_config.py` e la configurazione `labs/it/laboratorio/net/arti/arti.toml`, con il proxy su `-p 9150`. Quando non trova il binario **salta** la prova e lo segnala, senza considerarla superata: in quel caso il laboratorio va verificato a mano con i passi di questa pagina. Come nella guida, la richiesta `curl` del verificatore usa `--noproxy ""`, così che `NO_PROXY` non faccia aggirare il proxy SOCKS di Arti.

## Problemi noti

| Sintomo | Causa |
|---|---|
| `Lab 20: arti non compilato, saltato` | manca `labs/it/vendor/arti/target/release/arti` |
| Il bootstrap non finisce | la rete privata non è avviata, oppure `arti.toml` è stato generato per una rete rigenerata dopo: rilancia `arti_config.py` |
| `Permission denied` sulle cartelle di stato | Arti vuole permessi stretti sulle proprie directory: cancella `labs/it/laboratorio/net/arti/state` e riprova |
| `pkill -f "arti proxy"` o `pkill -x arti` termina processi non pertinenti | evita l'arresto per nome: lo script usa i PID di **questa** esecuzione e li libera con `trap` |
