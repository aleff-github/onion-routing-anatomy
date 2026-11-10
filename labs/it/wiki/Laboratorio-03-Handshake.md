# Laboratorio 3 — Handshake di circuito: ntor, ntor-v3, CREATE_FAST

| | |
|---|---|
| **Capitolo** | 9 — Costruire un circuito |
| **Serve la rete?** | sì |
| **Prerequisiti** | Laboratori 1 e 2; `cryptography`, `hashlib` (SHA-3, SHAKE) |
| **Tempo** | 3–4 ore per scriverlo, 1 minuto per rieseguirlo |
| **File** | `labs/it/codice/torlab/ntor.py` |

## Che cosa dimostra

Che un handshake crittografico si può implementare dalla specifica e farlo funzionare
contro un'implementazione indipendente — che è l'unica prova che valga. E che un relay
reagisce esattamente come prescritto quando qualcosa non torna: un bit cambiato nel MAC
produce un `DESTROY` con motivo `PROTOCOL`, non un messaggio d'errore utile.

Quattro handshake in un colpo solo: ntor-v3 semplice, ntor-v3 che negozia il controllo
della congestione, ntor classico e `CREATE_FAST`.

## Preparazione

```bash
make -C labs/it/laboratorio avvia
export PYTHONPATH=labs/it/codice
```

Le chiavi del relay (identità Ed25519 e `ntor-onion-key`) le legge per te
`torlab.laboratorio.relay("003r")`, dai file della rete di laboratorio e dai
microdescrittori del client — esattamente le stesse due righe che un client vero trova
nel consenso.

## Esecuzione

```bash
python3 - <<'EOF'
from torlab.canale import apri_canale
from torlab.celle import Cella, Comando, descrivi
from torlab.laboratorio import relay
from torlab.ntor import *

g = relay("003r")
c = apri_canale("127.0.0.1", g.porta, identita_attesa=g.id_ed)

def crea(circ, htype, hdata):
    c.invia(Cella(circ, Comando.CREATE2, corpo_create2(htype, hdata)))
    r = c.ricevi()
    print("<-", descrivi(r, c.versione))
    return r

# 1. ntor-v3, senza estensioni
st, hd = ntor3_client_inizio(g.id_ed, g.ntor, codifica_estensioni([]))
r = crea(0x80000001, HTYPE_NTOR_V3, hd)
sm, _ = ntor3_client_fine(st, hdata_created2(r.corpo))
print("   ntor-v3 ok, messaggio del relay:", decodifica_estensioni(sm))

# 2. ntor-v3 che chiede il controllo della congestione
st, hd = ntor3_client_inizio(g.id_ed, g.ntor, codifica_estensioni([(1, b"")]))
r = crea(0x80000002, HTYPE_NTOR_V3, hd)
sm, _ = ntor3_client_fine(st, hdata_created2(r.corpo))
print("   ntor-v3 con CC_FIELD_REQUEST ok, risposta:", decodifica_estensioni(sm))

# 3. ntor classico
st, hd = ntor_client_inizio(g.id_rsa, g.ntor)
ntor_client_fine(st, hdata_created2(crea(0x80000003, HTYPE_NTOR, hd).corpo))
print("   ntor ok")

# 4. CREATE_FAST (solo per circuiti di un salto: si appoggia al TLS)
x, corpo = create_fast_client()
c.invia(Cella(0x80000004, Comando.CREATE_FAST, corpo))
r = c.ricevi(); print("<-", descrivi(r, c.versione))
create_fast_completa(x, r.corpo); print("   CREATE_FAST ok")

# 5. un bit del MAC alterato di proposito
st, hd = ntor3_client_inizio(g.id_ed, g.ntor, codifica_estensioni([]))
r = crea(0x80000005, HTYPE_NTOR_V3, hd[:-1] + bytes([hd[-1] ^ 1]))
assert r.comando == Comando.DESTROY and r.corpo[0] == 1
print("   motivo:", r.corpo[0], "(MAC alterato)")

# 6. CGO chiesto senza controllo della congestione
st, hd = ntor3_client_inizio(g.id_ed, g.ntor, codifica_estensioni([(3, b"\x02\x06")]))
r = crea(0x80000006, HTYPE_NTOR_V3, hd)
assert r.comando == Comando.DESTROY and r.corpo[0] == 1
print("   motivo:", r.corpo[0], "(CGO chiesto senza controllo della congestione)")
EOF
```

## Output atteso

```
<- CircID=0x80000001 CREATED2 corpo=509 byte
   ntor-v3 ok, messaggio del relay: []
<- CircID=0x80000002 CREATED2 corpo=509 byte
   ntor-v3 con CC_FIELD_REQUEST ok, risposta: [(2, b'\x1f')]
<- CircID=0x80000003 CREATED2 corpo=509 byte
   ntor ok
<- CircID=0x80000004 CREATED_FAST corpo=509 byte
   CREATE_FAST ok
<- CircID=0x80000005 DESTROY corpo=509 byte
   motivo: 1 (MAC alterato)
<- CircID=0x80000006 DESTROY corpo=509 byte
   motivo: 1 (CGO chiesto senza controllo della congestione)
```

Come leggerlo:

- **`[(2, b'\x1f')]`** è la risposta del relay all'estensione 1: accetta il controllo
  della congestione e comunica `sendme_inc` = `0x1f` = **31**, cioè l'**intervallo di celle DATA tra i messaggi SENDME** previsto dal controllo della congestione. La proposta 324 sceglie 31 anche per la sua vicinanza alla capacità di un record TLS massimo, ma il parametro non impone alcuna suddivisione dei record TLS. Il valore ritorna nel [Laboratorio 5](Laboratorio-05-Stream.md) e nel descrittore onion del [Laboratorio 8](Laboratorio-08-Onion.md).
- **Motivo 1 = `PROTOCOL`.** Qui il relay può dire il motivo vero, perché l'errore è
  suo e non sta propagando il `DESTROY` di un altro nodo: in quel caso dovrebbe
  sostituirlo, per non rivelare informazioni lungo il circuito.
- L'ultimo caso mostra una dipendenza fra estensioni: CGO richiede il controllo della
  congestione, e chiederlo da solo non è una configurazione valida.
- **In questo output storico** non sono state osservate celle `PADDING`. La presenza del padding dipende dalla negoziazione, dai parametri e dall'uso del canale: non è garantita la sua assenza in tutte le reti o versioni Tor.

## Perché i vettori di test

Un handshake non si verifica facendolo funzionare: due implementazioni sbagliate allo
stesso modo si capirebbero benissimo. `test_ntor.py` riproduce i **vettori ufficiali**
— la proposta 332 per ntor-v3, la 216 per l'HKDF di ntor — con ingressi fissati, chiavi
«casuali» comprese, e uscite attese byte per byte. Altri test verificano che un `AUTH`
alterato o una stringa `VER` diversa facciano fallire l'handshake.

Un dettaglio che vale per tutto il libro: il confronto di `AUTH` usa
`hmac.compare_digest`, che evita un confronto con uscita immediata al primo byte diverso per dati dello stesso tipo e lunghezza. Ciò riduce rischi di timing, ma non dimostra che l'intera implementazione abbia tempi costanti.

## Verifica automatica

La funzione `lab3` del verificatore italiano `scripts/verify_labs.py` copre sei scenari di rete. È distinta dai test crittografici offline, avviabili dalla radice con `PYTHONPATH=labs/it/codice python3 -m pytest -q labs/it/codice/torlab/test/test_ntor.py`. La prima richiede la rete privata avviata; la seconda gira anche senza rete.

## Problemi noti

| Sintomo | Causa |
|---|---|
| `LookupError: nessun microdescrittore per 003r` | il client non ha ancora scaricato i microdescrittori: attendi un minuto dopo l'avvio, oppure la rete non ha completato il bootstrap |
| `CREATE2` riceve `DESTROY` (comando 4) | handshake non valido, estensione non supportata, chiavi obsolete o condizione temporanea: controlla il motivo e i log della rete privata prima di riprovare |
| `ErroreHandshake: AUTH ntor-v3 non valido` | stai usando le chiavi di un altro relay, o chiavi di una rete rigenerata |

---

# Il codice, in dettaglio

`labs/it/codice/torlab/ntor.py`, circa 240 righe. È il modulo che va scritto con la specifica
aperta accanto e verificato sui vettori di test: qui «funziona» non significa «è giusto».

## Le primitive

```python
NTOR3_PROTOID = b"ntor3-curve25519-sha3_256-1"
def _t(nome):  return NTOR3_PROTOID + b":" + nome.encode()
def _encap(s): return struct.pack(">Q", len(s)) + s
def _h3(s, t): return hashlib.sha3_256(_encap(t) + s).digest()
def _mac3(k, msg, t):
    return hashlib.sha3_256(_encap(t) + _encap(k) + msg).digest()
def _kdf3(s, t, n): return hashlib.shake_256(_encap(t) + s).digest(n)
```

Sette righe che sono la traduzione letterale dell'appendice A.1 della proposta 332. Tre
idee di progetto, tutte generali:

**Separazione di dominio.** Il `PROTOID` entra in ogni calcolo. Garantisce che un valore
prodotto qui non possa mai essere scambiato per un valore prodotto da un altro protocollo,
nemmeno se usasse le stesse chiavi e la stessa funzione di hash.

**I tweak.** Da un'unica funzione di hash si ricavano funzioni distinte, una per scopo:
`kdf_phase1`, `msg_mac`, `key_seed`, `verify`, `kdf_final`, `auth_final`. Senza, il digest
calcolato per autenticare potrebbe valere anche come chiave, e chi ottenesse l'uno avrebbe
l'altro.

**L'incapsulamento.** `_encap` antepone a ogni pezzo la sua lunghezza su 8 byte, e rende la
concatenazione **non ambigua**. Senza, le coppie (`"ab"`, `"c"`) e (`"a"`, `"bc"`) darebbero
in ingresso la stessa stringa `"abc"`, quindi lo stesso hash: si potrebbe spostare il
confine fra due campi e ottenere un MAC valido su dati diversi. È una classe di attacchi
nota, e l'unica difesa è codificare la **struttura**, non solo il contenuto.

Attenzione a un dettaglio: in `_mac3` la *chiave* è incapsulata e il messaggio no. È la
definizione della proposta. Renderla «più regolare» incapsulando entrambi romperebbe
l'interoperabilità con tor, e i test lo scoprirebbero subito.

## Fase 1: il messaggio del client

```python
def ntor3_client_inizio(ID, B, messaggio, ver=b"circuit extend", x=None):
    sk, X = x25519_genera(x)
    Bx = x25519_dh(sk, B)
    fase1 = _kdf3(Bx + ID + X + B + NTOR3_PROTOID + _encap(ver), _t("kdf_phase1"), 64)
    enc_k1, mac_k1 = fase1[:32], fase1[32:]
    msg_cifrato = aes_ctr(enc_k1, messaggio)
    mac = _mac3(mac_k1, ID + B + X + msg_cifrato, _t("msg_mac"))
    return StatoNtor3(sk, X, B, ID, Bx, mac, ver), ID + B + X + msg_cifrato + mac
```

Il client genera una coppia effimera (`sk`, `X`) e calcola **`Bx`**, cioè
Diffie-Hellman fra la propria chiave effimera e la chiave `ntor-onion-key` **statica** del
relay. Da lì derivano due chiavi: una per cifrare il proprio messaggio, una per
autenticarlo.

> **Questa parte non ha forward secrecy.** `Bx` dipende dalla chiave statica del relay: chi
> la ottenesse domani potrebbe decifrare i messaggi `CM` registrati oggi. È una proprietà
> nota e accettata, ed è il motivo per cui in `CM` ci vanno *opzioni negoziate*, non segreti.
> Il materiale del circuito, quello sì, è protetto in fase 2.

Il parametro `x` esiste solo per i test: permette di fissare la chiave «casuale» e
riprodurre i vettori della proposta byte per byte. Senza, l'handshake non sarebbe
verificabile in modo deterministico.

La stringa `ver` vale `b"circuit extend"` per l'estensione di circuito. Entra nel calcolo
incapsulata, quindi anche una differenza di un carattere produce chiavi diverse: è ciò che
impedisce di riusare un handshake fatto per uno scopo in un contesto diverso.

## Fase 2: la risposta del relay

```python
def ntor3_client_fine(st, risposta, lunghezza=72):
    Y, auth, msg = risposta[:32], risposta[32:64], risposta[64:]
    secret_input = (x25519_dh(st.x, Y) + st.Bx + st.ID + st.B + st.X + Y
                    + NTOR3_PROTOID + _encap(st.ver))
    key_seed = _h3(secret_input, _t("key_seed"))
    verify   = _h3(secret_input, _t("verify"))
    auth_input = (verify + st.ID + st.B + Y + st.X + st.mac + _encap(msg)
                  + NTOR3_PROTOID + b"Server")
    if not hmac.compare_digest(_h3(auth_input, _t("auth_final")), auth):
        raise ErroreHandshake("AUTH ntor-v3 non valido")
    flusso = _kdf3(key_seed, _t("kdf_final"), 32 + lunghezza)
    return aes_ctr(flusso[:32], msg), flusso[32:]
```

Il `secret_input` combina **due** Diffie-Hellman, e ciascuno serve a una cosa diversa:

| | Che cosa combina | A che serve |
|---|---|---|
| `Yx` (`x25519_dh(st.x, Y)`) | effimera del client × effimera del relay | **forward secrecy**: nessuna chiave a lungo termine lo può ricostruire |
| `Bx` | effimera del client × statica del relay | **autenticazione**: solo chi ha la chiave privata del relay può calcolarlo |

È il cuore di ntor: un solo scambio dà entrambe le proprietà. Togliendo `Bx` si perde
l'autenticazione e chiunque potrebbe spacciarsi per il relay; togliendo `Yx` si perde la
forward secrecy.

`hmac.compare_digest` non è pignoleria: impiega lo stesso tempo qualunque sia il primo byte
diverso. Un confronto ordinario (`==`) rivelerebbe, con misure ripetute, quanti byte
iniziali di un `AUTH` sono corretti — e da lì si costruisce un attacco.

Il flusso finale è più lungo delle chiavi del circuito: i primi 32 byte servono a decifrare
il messaggio del relay, il resto (72 byte) sono `Df`, `Db`, `Kf`, `Kb`
([Laboratorio 4](Laboratorio-04-Cifratura.md)).

## I vettori di test e i loro limiti

I vettori ufficiali forniscono una verifica riproducibile dell'aderenza agli esempi pubblicati, ma da soli non dimostrano la sicurezza di ogni percorso di esecuzione.

```python
def test_ntor3_vettori_proposta_332():
    st, hdata = ntor3_client_inizio(h(V["ID"]), h(V["B"]), h(V["CM"]),
                                    ver=h(V["VER"]), x=h(V["x"]))
    assert hdata.hex() == V["client"]
    sm, flusso = ntor3_client_fine(st, h(V["server"]), lunghezza=256)
    assert sm == h(V["SM"])
    assert flusso[:32].hex() == V["keystream_inizio"]
```

Un handshake crittografico **non si verifica facendolo funzionare**: due implementazioni
sbagliate nello stesso modo si capirebbero benissimo. Si verifica con valori di ingresso
fissati — comprese le chiavi «casuali» — e uscite attese byte per byte.

`test_ntor.py` riproduce il vettore completo della proposta 332 e quelli della proposta 216
per l'HKDF di ntor. Altri test verificano che un `AUTH` alterato o una stringa `ver` diversa
facciano **fallire** l'handshake: un verificatore che accetta tutto passerebbe il test
positivo.

## Le quattro varianti, e quando usarle

| Handshake | Quando | Note |
|---|---|---|
| **ntor-v3** | sempre, oggi | permette di negoziare opzioni nel messaggio cifrato |
| **ntor** | relay che non supportano `Relay=4` | nessun messaggio, solo chiavi |
| **CREATE_FAST** | solo circuiti di **un salto** | non c'è DH: la sicurezza è quella del TLS sottostante |
| TAP | mai | rimosso in tor 0.4.9.1-alpha |

`CREATE_FAST` va usato solo dove il primo salto è anche l'ultimo — richieste di directory,
per esempio — perché non aggiunge nulla al TLS. Usarlo per il primo salto di un circuito
vero significherebbe che chi compromette il guard ottiene anche le chiavi del circuito.

## Che cosa serve sapere per farlo funzionare

- **Le chiavi del relay** (identità Ed25519 e `ntor-onion-key`) le legge
  `torlab.laboratorio.relay("003r")` dai file della rete e dai microdescrittori del client.
  Se il client non li ha ancora scaricati, ottieni `LookupError`: aspetta un minuto dopo
  l'avvio della rete.
- **Un CircID nuovo per ogni prova.** Riusarne uno già aperto fa rispondere `DESTROY`.
- Il bit alto del CircID dev'essere a 1 (`0x80000001`, non `0x00000001`): lo impone la
  specifica per chi ha aperto il canale, ed è il meccanismo che evita collisioni fra i
  CircID scelti dalle due estremità.
- L'handshake non apre nulla: dopo un `CREATED2` hai un circuito di un salto e delle
  chiavi, e niente su cui mandare dati finché non arriva il [Laboratorio 4](Laboratorio-04-Cifratura.md).

## Da dove vengono queste formule

| Nel codice | Nella fonte |
|---|---|
| primitive, tweak, ENCAP | proposta 332, appendice A.1 |
| fase 1 e fase 2 del client | proposta 332, *Client operation* |
| vettori di test | proposta 332 (ntor-v3), proposta 216 (ntor) |
| formato di CREATE2/CREATED2 | tor-spec, *CREATE and CREATED cells* |
| negoziazione delle estensioni | tor-spec, *Sending extensions in the circuit extension handshake* |
