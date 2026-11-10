# Laboratorio 1 — Aprire un canale verificato

| | |
|---|---|
| **Capitolo** | 7 — Canali: TLS e handshake di collegamento |
| **Serve la rete?** | sì |
| **Prerequisiti** | Laboratorio 2 (`celle.py`); `cryptography` |
| **Tempo** | 2–3 ore per scriverlo, 1 minuto per rieseguirlo |
| **File** | `labs/it/codice/torlab/canale.py` |

## Che cosa dimostra

Che il certificato TLS di un relay **non conta nulla**: è autofirmato, e chiunque può
generarne uno uguale. L'identità di un relay si dimostra dentro il canale, con la cella
`CERTS`, che lega l'identità Ed25519 a una chiave di firma e quest'ultima all'impronta
del certificato TLS in uso. Verificare quella catena, e poi confrontarla con l'identità
che ci si aspettava, è l'unica cosa che impedisce a un intermediario di mettersi in mezzo.

## Preparazione

```bash
make -C labs/it/laboratorio avvia      # se la rete non è già in piedi
export PYTHONPATH=labs/it/codice
```

## Esecuzione

```bash
python3 - <<'EOF'
from torlab.canale import apri_canale, identita_da_file

atteso = identita_da_file("labs/it/laboratorio/net/nodes/003r/fingerprint-ed25519")
c = apri_canale("127.0.0.1", 5103, identita_attesa=atteso)
print(c.versione, c.identita_ed.hex()[:16] + "...", c.netinfo, c.metodi_auth)
for r in c.registro:
    print("  ", r)

# e ora il controllo negativo: il relay giusto, ma l'identità di un altro
try:
    apri_canale("127.0.0.1", 5104, identita_attesa=atteso)
except Exception as e:
    print("porta 5104 con l'identità di 003r ->", e)
EOF
```

## Output atteso

```
5 785d3199f21d20ad... Netinfo(orario=1790265613, tuo_indirizzo='127.0.0.1', miei_indirizzi=['127.0.0.1']) [3]
   TLS TLSv1.3 TLS_AES_256_GCM_SHA384
   <- VERSIONS (6 byte)
   <- CERTS (1456 byte)
   <- AUTH_CHALLENGE (36 byte)
   <- NETINFO (509 byte)
   -> NETINFO: canale aperto

porta 5104 con l'identità di 003r -> il relay ha un'identità diversa da quella attesa
```

Come leggerlo:

- **`5`** è la versione del link protocol negoziata. Offriamo la 4 e la 5, come Arti:
  la 3 è ormai inutile.
- L'identità in esadecimale **sarà diversa dalla tua**: ogni volta che la rete di
  laboratorio viene rigenerata, i nodi prendono chiavi nuove. Lo stesso vale per la
  lunghezza della `CERTS`, che dipende dai certificati.
- **`[3]`** sono i metodi di autenticazione che il relay accetterebbe da un altro relay.
  Noi siamo un client e non ci autentichiamo: un client che si autenticasse si
  costruirebbe un'identità riconoscibile da un canale all'altro, cioè l'esatto contrario
  di ciò che vuole.
- Nella `NETINFO` il relay dichiara l'ora e ci dice quale indirizzo ci vede. La nostra
  `NETINFO` di risposta porta **orario zero e nessun indirizzo**: un client non rivela né
  l'ora del proprio orologio né i propri indirizzi.
- Il canale resta **silenzioso**: nessuna cella `PADDING`. Il padding di collegamento si
  attiva solo sui canali che portano traffico vero, e finché non c'è un circuito che
  prosegue oltre il relay, per lui questo canale non è «in uso». Lo si vedrà comparire
  nel [Laboratorio 4](Laboratorio-04-Cifratura.md).

## Il controllo che conta

L'ultima riga è la parte importante del laboratorio. Ci colleghiamo a `004r` dichiarando
di aspettarci `003r`, e il codice rifiuta. Un'implementazione che verifica firme e
scadenze ma **non** confronta l'identità con quella attesa passa tutti i test positivi e
non protegge da nulla: accetterebbe qualunque relay si presenti al posto di quello
scelto.

## Verifica automatica

Il controllo `lab1` apre un canale verso `003r`, `006e` e `000a`, controlla la sequenza
delle celle dell'handshake e ripete il controllo negativo.

I test senza rete (`test_canale.py`) costruiscono una catena di certificati valida con
due chiavi generate al momento e poi la guastano in tutti i modi previsti dalla
specifica: firma alterata, chiave di firma non certificata, impronta TLS diversa,
certificato scaduto, tipo duplicato. Ogni guasto dev'essere rilevato.

## Problemi noti

| Sintomo | Causa |
|---|---|
| `ConnectionRefusedError` sulla 5103 | la rete non è avviata: `make -C labs/it/laboratorio stato` |
| `il relay ha un'identità diversa da quella attesa` sulla porta giusta | hai rigenerato la rete e stai usando un'impronta vecchia: rileggi `fingerprint-ed25519` |
| `cella inattesa durante l'handshake` | stai parlando con qualcosa che non è un relay Tor (la porta sbagliata) |

## Da qui

Il canale è il fondamento di tutto: il [Laboratorio 3](Laboratorio-03-Handshake.md) ci
costruisce sopra i circuiti.

---

# Il codice, in dettaglio

`labs/it/codice/torlab/canale.py`, circa 260 righe. Fa tre cose: apre una connessione TLS,
verifica chi c'è dall'altra parte, e consegna un oggetto `Canale` su cui gli altri
laboratori spediscono celle.

## Perché il TLS non basta

```python
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
```

Tre righe che a un occhio esperto di sicurezza sembrano un errore grave, e non lo sono.

Il certificato TLS di un relay Tor è **autofirmato** e non contiene alcun nome di dominio
verificabile: non esiste una CA che certifichi i relay, e non avrebbe senso che esistesse.
Chiedere a Python di verificarlo farebbe fallire ogni connessione. La verifica dell'identità
avviene **dentro** il canale, con la cella `CERTS`, e la connessione TLS che la trasporta vi
viene agganciata dall'impronta del proprio certificato.

In altre parole: il TLS serve a cifrare, non a autenticare. Chi autentica è Tor.

> Se copi queste tre righe in un programma che parla con un server web, hai disattivato
> ogni protezione. Qui funzionano perché **subito dopo** c'è la verifica della catena, ed è
> più stringente di quella di una CA: lega la sessione a una chiave che hai deciso tu in
> anticipo.

```python
if os.environ.get("SSLKEYLOGFILE"):
    ctx.keylog_filename = os.environ["SSLKEYLOGFILE"]
```

È la convenzione dei browser: se la variabile d'ambiente è impostata, la libreria vi scrive
i segreti della sessione TLS, e Wireshark può decifrare la cattura. È ciò che rende
possibile il [Laboratorio 12](Laboratorio-12-Traffico.md) — e nota che decifriamo **il nostro**
traffico, con chiavi che il nostro programma esporta di sua volontà.

```python
sorgente = (origine, 0) if origine else None
```

Il parametro `origine` sceglie l'indirizzo locale da cui partire, per esempio `127.0.0.2`.
Serve solo al [Laboratorio 9](Laboratorio-09-DoS.md), dove le difese anti-DoS contano per
indirizzo di provenienza e servono contatori separati fra una prova e l'altra.

## La catena dei certificati

```python
def verifica_identita_responder(certificati, cert_tls_der):
    id_v_sign  = decodifica_cert_ed(certificati[4])   # IDENTITY_V_SIGNING
    sign_v_tls = decodifica_cert_ed(certificati[5])   # SIGNING_V_TLS_CERT
    identita = id_v_sign.chiave_firmataria            # estensione 4
    id_v_sign.verifica_firma(identita)                # auto-firmato
    chiave_firma = id_v_sign.chiave_certificata       # KP_relaysign_ed
    sign_v_tls.verifica_firma(chiave_firma)
    if sign_v_tls.chiave_certificata != sha256(cert_tls_der).digest():
        raise ErroreCanale("non corrisponde al certificato TLS")
    for c in (id_v_sign, sign_v_tls):
        if c.scaduto():
            raise ErroreCanale("certificato scaduto")
    return identita
```

Otto righe che decidono tutto. Ciascuna chiude una porta:

| | Che cosa fa | Che cosa impedisce |
|---|---|---|
| tipo 4 | lega l'identità del relay alla sua chiave di firma | che una chiave di firma qualsiasi si spacci per quella del relay |
| `chiave_firmataria` | legge **chi** firma dall'estensione 4 | di dedurre l'identità invece di leggerla |
| auto-firma | verifica che il tipo 4 sia coerente con sé stesso | poco, da solo: chiunque può generarne uno |
| tipo 5 | lega la chiave di firma al certificato TLS | che la catena sia scollegata dalla sessione |
| impronta SHA-256 | lega il tutto a **questa** connessione | che un intermediario presenti i certificati di un relay onesto sulla propria connessione |
| scadenze | rifiuta certificati vecchi | di accettare una chiave di firma dismessa |

Il punto più importante è il confronto con l'impronta del certificato TLS. Senza, la catena
sarebbe vera e inutile: dimostrerebbe che *esiste* un relay con quell'identità, non che
stiamo parlando con lui.

**L'identità non è un campo del certificato**: è la chiave che lo ha firmato, e sta
nell'estensione 4. Il certificato dice «io, X, certifico la chiave Y»: il nome X va letto
dall'estensione, non dedotto da dove si è preso il certificato.

## Il controllo che manca in questa funzione

```python
identita = verifica_identita_responder(certificati, cert_tls)
if identita_attesa is not None and identita != identita_attesa:
    raise ErroreCanale("il relay ha un'identità diversa da quella attesa")
```

Una catena valida dimostra che stiamo parlando con **un** relay, non che stiamo parlando
con **quel** relay. Il confronto con l'identità attesa è la riga che trasforma
«autenticazione» in «autenticazione di chi volevo io», ed è quella che nel laboratorio
facciamo fallire apposta collegandoci alla porta 5104 con l'impronta di `003r`.

Un'implementazione che verifica firme e scadenze ma salta questo confronto passa tutti i
test positivi e non protegge da niente.

## Il ciclo dell'handshake

```python
while netinfo is None:
    cella, buffer = _leggi(sock, buffer, versione)
    if cella.comando == Comando.VERSIONS:
        if versione:
            continue                      # VERSIONS successive: ignorate
        versione = negozia_versione(VERSIONI_SUPPORTATE, cella.corpo)
    elif cella.comando == Comando.VPADDING:
        continue
    elif cella.comando == Comando.CERTS:
        certificati = decodifica_certs(cella.corpo)
    elif cella.comando == Comando.AUTH_CHALLENGE:
        (n,) = struct.unpack(">H", cella.corpo[32:34])
        metodi = [m for (m,) in struct.iter_unpack(">H", cella.corpo[34:34 + 2 * n])]
    elif cella.comando == Comando.NETINFO:
        netinfo = decodifica_netinfo(cella.corpo)
    else:
        raise ErroreCanale(f"cella inattesa durante l'handshake: {cella.comando}")
```

- **La condizione d'uscita è l'arrivo della `NETINFO`**, non un numero di celle: l'handshake
  finisce quando il relay dice che è finito, e le celle intermedie possono essere di più o
  di meno.
- Una `VERSIONS` dopo la prima si **ignora**: lo prescrive la specifica, e senza quel
  `continue` un relay potrebbe farci rinegoziare la versione a metà handshake.
- La `AUTH_CHALLENGE` la leggiamo solo per annotarne i metodi. Siamo un client e non ci
  autenticheremo: autenticarsi darebbe al relay un'identità stabile da un canale all'altro,
  che è esattamente ciò che un client non vuole avere.
- L'ultimo ramo è il più importante, e va letto al contrario: **tutto ciò che non è previsto
  è un errore**. Il `VPADDING` si scarta in silenzio perché la specifica lo consente in
  qualunque momento; qualsiasi altra cella durante l'handshake significa che dall'altra
  parte non c'è un relay Tor, e si chiude. Un ciclo con un `else: pass` finale sembrerebbe
  più tollerante e accetterebbe, senza dirlo, qualunque sequenza.

Subito dopo il ciclo c'è un controllo facile da dimenticare:

```python
if certificati is None:
    raise ErroreCanale("NETINFO ricevuto prima di CERTS")
```

Senza, un relay potrebbe mandare direttamente la `NETINFO` e saltare del tutto
l'autenticazione: il ciclo finirebbe, e `verifica_identita_responder` riceverebbe `None`.

## La nostra NETINFO

```python
canale.invia(cella_netinfo_client(host))
```

La `NETINFO` che inviamo porta **orario zero e nessun indirizzo proprio**. Non è una
semplificazione del laboratorio: è quello che fa un client vero. Dichiarare l'ora del
proprio orologio significa offrire un identificatore (lo scarto dell'orologio è
sorprendentemente stabile e distintivo); dichiarare i propri indirizzi significa
dichiararsi raggiungibile, cosa che un client non è.

## Che cosa serve sapere per farlo funzionare

- **Le impronte cambiano a ogni rigenerazione della rete.** `identita_da_file` legge
  `labs/it/laboratorio/net/nodes/<nodo>/fingerprint-ed25519`, che contiene `<nome> <chiave base64>` senza
  il riempimento `=`: per questo il codice lo riaggiunge prima di decodificare.
- **La porta è `5100 + numero del nodo`**, sempre.
- Il canale **non** invia celle di padding e non tiene vivo nulla: se lo lasci aperto senza
  usarlo, il relay lo chiuderà dopo qualche minuto (capitolo 7).
- Un canale nuovo non riceve `PADDING`: il relay lo padda solo quando il canale ha portato
  un circuito **completo** (uno che prosegue oltre di lui) o traffico dell'utente — in
  `channelpadding.c` sono gli stati `CHANNEL_USED_FOR_FULL_CIRCS` e
  `CHANNEL_USED_FOR_USER_TRAFFIC`. I nostri circuiti di un salto non contano, e il padding
  compare solo nel [Laboratorio 4](Laboratorio-04-Cifratura.md). Superata quella soglia,
  però, il padding parte **prima** del primo traffico applicativo: è il parametro di
  consenso `nf_pad_before_usage`, che vale 1 per impostazione predefinita.

## Da dove vengono queste regole

| Nel codice | Nella specifica |
|---|---|
| sequenza dell'handshake | tor-spec, *Negotiating and initializing channels* |
| verifica dei certificati | tor-spec, *Authenticating the responder from its CERTS* |
| formato dei certificati Ed25519 | cert-spec, *Tor Ed25519 Certificates* |
| tipi 4 e 5, estensione 4 | cert-spec, *Certificate types (CERT_TYPE field)* |
| contenuto della NETINFO | tor-spec, *NETINFO cells* |
| formato della AUTH_CHALLENGE | tor-spec, *AUTH_CHALLENGE cells* |
