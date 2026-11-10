# Laboratorio 7 — Selezione pesata dei percorsi

| | |
|---|---|
| **Capitolo** | 13 — La scelta del percorso |
| **Serve la rete?** | no (usa un consenso reale salvato su disco) |
| **Prerequisiti** | Laboratorio 6 (`directory.py`) |
| **Tempo** | 2 ore per scriverlo, 1 minuto per rieseguirlo |
| **File** | `labs/it/codice/torlab/percorso.py` |

## Che cosa dimostra

**Limiti del modello didattico:** i pesi per posizione sono calcolati sui relay idonei e la procedura sceglie exit, guard e middle mediante campionamento con rifiuto. Non si tratta dell'intero algoritmo Tor: mancano le famiglie, i controlli completi delle exit policy per la destinazione, i campioni di guard persistenti e alcuni casi IPv6 e onion. Inoltre `probabilita()` mostra i pesi dei candidati **prima** delle esclusioni condizionate fra hop, non l'esatta probabilità marginale di apparire in un circuito completo.

Che la scelta dei tre relay di un circuito non è casuale in senso ingenuo: ogni relay è
estratto con probabilità proporzionale alla sua banda, corretta da un peso che dipende
dal tipo di relay (guard, exit, entrambi, nessuno dei due) e dalla posizione nel
circuito. Sopra questa estrazione agiscono i vincoli: tre relay distinti, in tre reti
/16 distinte, un guard in prima posizione e un exit in terza.

Il laboratorio lavora sul **consenso pubblico**, non sulla rete di laboratorio: la rete
privata ha dieci nodi e non dice nulla di interessante sulle proporzioni.

## Preparazione

Serve un consenso reale: **non è versionato nella repository**. La ricerca originale utilizzava un'istantanea scaricata da
[CollecTor](https://collector.torproject.org/), l'archivio pubblico del Tor Project:

```
labs/it/dati/collector/consensus-microdesc-2026-09-23-15
```

Si scarica una volta sola, dalla radice del repository:

```bash
make -C labs/it data
```

Il comando estrae quel consenso dall'archivio mensile di CollecTor e lo salva nel percorso
qui sopra. Controlla solo l'intestazione del formato, **non le firme delle autorità**: per
verificarle serve il Laboratorio 6 con i certificati (vedi il
[Laboratorio 15](Laboratorio-15-Metriche.md)). Dettagli in `labs/it/dati/README.md`.

I numeri qui sotto valgono per quel consenso: con un altro consenso cambieranno di poco,
ma cambieranno.

Sono dati pubblicati apposta per la ricerca: scaricarli non tocca alcun utente della rete.

La sezione `recent/` non conserva i documenti indefinitamente: se non è disponibile, estrai `2026-09-23-15-00-00-consensus-microdesc` dall'archivio mensile [CollecTor settembre 2026](https://collector.torproject.org/archive/relay-descriptors/microdescs/microdescs-2026-09.tar.xz). `make -C labs/it data` lo fa automaticamente e salva il file in `labs/it/dati/collector/`. Non usare il consenso della rete privata da otto nodi per riprodurre le statistiche della rete pubblica.

## Esecuzione

```bash
export PYTHONPATH=labs/it/codice
python3 - <<'EOF'
import random
from collections import Counter
from torlab.directory import analizza_consenso
from torlab.percorso import Selettore, probabilita, quota_primi, _tipo, rete16
from torlab.metriche import riassunto

c = analizza_consenso(open("labs/it/dati/collector/consensus-microdesc-2026-09-23-15").read())
r = riassunto(c)
print(f"relay: {r['relay']}")
print(f"banda con Guard: {100*r['quota_banda_guard']:.1f}%    "
      f"banda con Exit: {100*r['quota_banda_exit']:.1f}%")

for pos in ("guard", "middle", "exit"):
    p = probabilita(c, pos)
    print(f"{pos:<6}: idonei {len(p):>5}; "
          f"primi 10 = {100*quota_primi(p, 10):.1f}%; primi 100 = {100*quota_primi(p, 100):.1f}%")

sel, rng = Selettore(c), random.Random(7)          # seme fisso: risultati riproducibili
g, m, e = sel.percorso(rng)
# Nel caso ordinario, senza guard esterno già fissato:
assert len({x.id_rsa for x in (g, m, e)}) == 3
assert len({rete16(x) for x in (g, m, e)}) == 3
assert "Guard" in g.flag and "Exit" in e.flag and "BadExit" not in e.flag
for nome, x in (("guard", g), ("middle", m), ("exit", e)):
    print(f"{nome:<6} {x.nome:<20} {x.ip:<16} /16 {rete16(x):<8} banda {x.banda}")

tipi = Counter("".join(_tipo(x) for x in sel.percorso(rng)) for _ in range(20000))
print("20000 percorsi:", "  ".join(f"{k} {100*v/20000:.1f}%" for k, v in tipi.most_common()))
EOF
```

## Output atteso

**Non usare questo generatore per circuiti reali:** `random.Random(7)` produce una sequenza intenzionalmente prevedibile per ripetere la simulazione; non sostituisce una sorgente casuale crittograficamente adeguata alla scelta dei percorsi di un client Tor.

**Output dell'esecuzione di riferimento** sul consenso del 23 settembre 2026: dipende dall'identità esatta del consenso e dalla versione del codice. La fissazione di `random.Random(7)` rende ripetibili le estrazioni solo a parità degli altri input. `probabilita()` include nella conta degli «idonei» anche i relay con peso zero: il numero di chiavi nel dizionario non coincide necessariamente con la lista dei candidati effettivamente estratti dal selettore.

```
relay: 9358
banda con Guard: 70.1%    banda con Exit: 33.1%
guard : idonei  5306; primi 10 = 1.7%; primi 100 = 12.6%
middle: idonei  8961; primi 10 = 2.8%; primi 100 = 13.7%
exit  : idonei  3126; primi 10 = 2.3%; primi 100 = 13.7%
20000 percorsi: gge 30.9%  ggd 29.4%  gme 20.4%  gmd 19.3%
```

(La riga con il singolo percorso mostra tre relay diversi a ogni consenso: quello che
conta è che le tre reti /16 siano diverse.)

Come leggerlo:

- Le sigle dell'ultima riga indicano il tipo dei tre relay: `g` guard, `e` exit puro,
  `d` guard **e** exit insieme, `m` né l'uno né l'altro. `gge` è un percorso con un
  guard, un relay con flag Guard in mezzo e un exit puro.
- **Nessun percorso** ha un relay con flag Exit in prima o seconda posizione: nel consenso
  del 23 settembre 2026 i pesi `Wme`, `Wmd` e `Wgd` valgono zero, perché la banda di
  uscita è la risorsa scarsa e non va sprecata dove non serve.
- Nel 60 % dei casi il relay di mezzo ha il flag Guard (`gg*`): i guard sono tanti e
  grossi, e in seconda posizione non c'è ragione di evitarli.
- La concentrazione è bassa: i dieci exit più probabili valgono insieme il 2,3 % delle
  scelte. Una rete in cui pochi relay assorbono gran parte del traffico sarebbe molto
  più facile da attaccare.

**Il seme conta.** L'ultima riga è un campione: con `random.Random(7)` escono questi
valori, con un altro seme cambiano di qualche decimo di punto. Senza fissare il seme
non si può confrontare una esecuzione con un'altra.

## Verifica automatica

Il verificatore `lab7` utilizza un consenso pubblico scaricato e costruisce 500 percorsi. I test unitari `labs/it/codice/torlab/test/test_percorso.py`, invece, utilizzano il consenso privato da otto relay e impostano `distinte_reti=False` quando devono costruire percorsi, perché tutti gli IP sono in `127.0/16`. Questi test non sono la verifica della diversità /16 su un consenso pubblico.


Il controllo `lab7` in `make verifica-lab` costruisce 500 percorsi e verifica i quattro
invarianti: tre identità distinte, tre reti /16 distinte, un guard in testa, un exit in
coda.

Attenzione a un dettaglio che mi è costato un errore: i **nickname non sono unici** nella
rete pubblica (151 sono usati da più relay). Due relay si confrontano per `id_rsa`, mai
per nome.

## Problemi noti

- `FileNotFoundError` sul consenso: vedi *Preparazione*.
- La costruzione dei 20000 percorsi richiede circa 7 secondi. Se ne impiega centinaia,
  stai usando una versione del `Selettore` che ricalcola i pesi a ogni estrazione: i
  pesi vanno calcolati una volta sola nel costruttore.

## Da qui

- [Laboratorio 15 — Statistiche del consenso](Laboratorio-15-Metriche.md) usa lo stesso file.
- [Laboratorio 19 — Tempo alla prima compromissione](Laboratorio-19-Simulazione.md) usa
  questo selettore per simulare sei mesi di traffico.

---

# Il codice, in dettaglio

`labs/it/codice/torlab/percorso.py`, circa 105 righe. Traduce in codice due documenti: le regole di
scelta del percorso (path-spec) e i pesi di banda (dir-spec).

## Il tipo di un relay

```python
def _tipo(r: VoceRelay) -> str:
    """g = solo Guard, e = solo Exit, d = Guard ed Exit, m = nessuno dei due."""
    g, e = "Guard" in r.flag, "Exit" in r.flag and "BadExit" not in r.flag
    return {(True, True): "d", (True, False): "g", (False, True): "e", (False, False): "m"}[(g, e)]
```

`BadExit` entra nella **definizione** di exit: un relay marcato così dalle autorità ha il
flag `Exit` ma non va usato per uscire. Dimenticarlo significa mandare traffico proprio ai
relay che le autorità hanno segnalato come ostili o mal configurati — nel consenso del 23
settembre 2026 sono 32.

Le quattro lettere sono quelle del consenso: `d` per chi è insieme guard ed exit (*dual*),
`m` per chi non è né l'uno né l'altro (*middle*).

## Il peso

```python
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
```

Il nome del peso si **compone**: prima lettera la posizione, seconda il tipo di relay.
`Wmg` è dunque «quanto pesa un guard quando lo si sceglie come middle». Comporre il nome
invece di scrivere una catena di `if` rende il codice una traduzione diretta della tabella
`bandwidth-weights` del consenso, e quindi verificabile leggendola.

Tre dettagli:

- un relay senza banda dichiarata pesa zero e non viene scelto; una banda negativa o non intera
  è invece un errore del consenso;
- il valore predefinito `scale` significa «peso pieno», e serve per i pesi che il consenso
  non elenca;
- la divisione per `scale` riporta il peso a un fattore fra 0 e 1: nel consenso i pesi sono
  interi da dividere per il parametro `bwweightscale` (predefinito 10000), perché il formato
  dei documenti non ammette numeri con la virgola. Il `Selettore` legge `bwweightscale` dai
  parametri del consenso.

Nel consenso del 23 settembre 2026, `Wme`, `Wmd` e `Wgd` valgono **zero**: per questo
nessun relay con il flag `Exit` compare mai in prima o seconda posizione. La banda di uscita
è la risorsa scarsa della rete, e i pesi la riservano a dove serve.

## Perché i pesi si calcolano una volta sola

I relay con peso effettivo nullo non compaiono nelle liste di `Selettore.candidati`, ma `probabilita()` li mantiene nel dizionario con valore zero. I conteggi degli idonei nella prima tabella comprendono quindi anche possibili candidati non estraibili.

```python
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
```

Una prima versione di questo laboratorio filtrava gli oltre novemila relay e ne ricalcolava
i pesi **a ogni estrazione**: 310 secondi per 2000 percorsi. Questa ne costruisce 20 000 in
7. In una simulazione statistica le prestazioni non sono un dettaglio ma la differenza fra
un esperimento che si può ripetere e uno che no.

I relay con peso zero si tolgono subito dalla lista: tenerli significherebbe estrarli e
scartarli, all'infinito.

## I vincoli, applicati per rifiuto

```python
    def scegli(self, pos: str, esclusi: list[VoceRelay], rng: random.Random,
               distinte_reti: bool = True, tentativi: int = 1000) -> VoceRelay:
        """Estrae per rifiuto; esauriti i tentativi, sceglie fra i soli relay compatibili."""
        ...
        excluded_ids = {r.id_rsa for r in esclusi}
        excluded_nets = {rete16(r) for r in esclusi} if distinte_reti else set()
        candidati, reti = self.candidati[pos], self.reti[pos]
        ...
        for _ in range(tentativi):
            i = rng.choices(indici, cum_weights=self.cumulati[pos])[0]
            if candidati[i].id_rsa not in excluded_ids and reti[i] not in excluded_nets:
                return candidati[i]
        pairs = [(r, w) for r, w, n in zip(candidati, self.pesi[pos], reti)
                 if r.id_rsa not in excluded_ids and n not in excluded_nets]
        if not pairs:
            raise LookupError(f"nessun relay idoneo per la posizione {pos}")
        return rng.choices([r for r, _ in pairs], weights=[w for _, w in pairs])[0]
```

Due relay sono «lo stesso relay» se hanno la stessa identità RSA, non se sono lo stesso oggetto
Python. Il vincolo di rete copre solo gli indirizzi IPv4 (`/16`): la specifica prevede anche
IPv6 (normalmente `/32`) e alcune eccezioni che dipendono dal tipo di circuito, che questo
modello non riproduce.

I vincoli non si applicano filtrando la lista prima dell'estrazione, ma **estraendo e
scartando**. Su una rete grande costa meno: i casi da scartare sono pochissimi, e rifiltrare
novemila relay a ogni scelta costerebbe molto di più.

I tentativi sono limitati a 1000 perché, su una rete piccola, il rifiuto potrebbe non
terminare: se quasi tutti i candidati sono nella stessa /16, le estrazioni valide sono rare.
Esauriti i tentativi, `scegli` filtra i soli relay compatibili e sceglie fra quelli; se non
ne resta nessuno, solleva un'eccezione chiara invece di bloccarsi.

> **I nickname non sono unici.** Nel consenso pubblico 151 nickname sono usati da più relay.
> Confrontare per nome, invece che per identità, produce codice che sembra funzionare e
> sbaglia in silenzio. Mi è successo scrivendo il controllo automatico di questo laboratorio.

## L'ordine di scelta

```python
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
```

Prima l'**exit**, poi il guard, infine il middle. Non è arbitrario: l'exit è il nodo più
vincolato, perché deve poter uscire verso la destinazione richiesta. Sceglierlo per ultimo
significherebbe spesso scoprire che nessun exit compatibile resta disponibile, e dover
ricominciare.

Il parametro `guard` permette di fissarlo dall'esterno: è così che il
[Laboratorio 19](Laboratorio-19-Simulazione.md) simula i guard persistenti. Un guard fissato
viene prima cercato fra i candidati idonei del consenso (se non c'è, `LookupError`), e l'exit
viene poi scelto escludendolo per identità e per rete /16: i vincoli valgono anche in questo caso.

## Che cosa questo modello non fa

**Limiti del modello didattico:** i pesi per posizione sono calcolati sui relay idonei e la procedura sceglie exit, guard e middle mediante campionamento con rifiuto. Non si tratta dell'intero algoritmo Tor: mancano le famiglie, i controlli completi delle exit policy per la destinazione, i campioni di guard persistenti e alcuni casi IPv6 e onion. Inoltre `probabilita()` mostra i pesi dei candidati **prima** delle esclusioni condizionate fra hop, non l'esatta probabilità marginale di apparire in un circuito completo.

Il modulo implementa i vincoli principali, non tutti. Mancano di proposito:

- le **famiglie** di relay, che richiedono i microdescrittori (è un esercizio del libro);
- i guard persistenti con campione, filtrati, confermati e primari;
- i vanguards per gli onion service;
- l'isolamento degli stream e le preferenze di porta.

Un modello che li includesse tutti sarebbe più realistico e molto meno istruttivo: non si
capirebbe più da dove viene il risultato. È una scelta che vale per tutto `torlab`.

## Da dove vengono queste regole

| Nel codice | Nella specifica |
|---|---|
| vincoli di scelta | path-spec, *Path selection and constraints* |
| pesi per posizione | path-spec, *Weighting node selection* |
| valori `W**` | dir-spec, *Computing Bandwidth Weights* |
| flag dei relay | dir-spec, *Assigning flags in a vote* |
