# Laboratorio 13 — Un onion service con scoperta ristretta

| | |
|---|---|
| **Capitolo** | 21 — Gestire un onion service |
| **Serve la rete?** | sì |
| **Prerequisiti** | Laboratorio 8 |
| **Tempo** | 1–2 ore |
| **File** | `labs/it/laboratorio/scoperta_ristretta.py` |

## Che cosa dimostra

Che si può pubblicare un onion service **raggiungibile solo da chi ha una chiave**, e
che chi non ce l'ha non arriva nemmeno a sapere che cosa offre: scarica il descrittore,
perché è pubblico, ma non riesce a decifrarne lo strato interno, quindi non conosce i
punti di introduzione, quindi non può contattare il servizio.

La scoperta ristretta (*client authorization*) non è un controllo d'accesso applicativo
messo davanti a un servizio: agisce prima, sulla scoperta stessa.

## Preparazione

```bash
make -C labs/it/laboratorio avvia
export PYTHONPATH=labs/it/codice
```

Lo script fa tutto da solo ed è rieseguibile: genera una coppia di chiavi X25519 per il
client, la installa fra i client autorizzati del servizio `009h`, prova ad accedere
senza e con la chiave, e alla fine **ripristina la configurazione di partenza**.
Per non eliminare dati non suoi, crea un file marcatore nelle directory temporanee
`hs_ristretto/` e `onion_auth/`: durante la pulizia cancella solo quelle marcate.
**Se trova cartelle preesistenti senza marcatore, si ferma con un errore**:
non aggirare la protezione prima di controllarne e salvare il contenuto.
Il file privato `.auth_private` è creato con permessi `0600` e non viene
sovrascritto.

## Esecuzione

```bash
python3 labs/it/laboratorio/scoperta_ristretta.py
```

## Output atteso

```
servizio ristretto: 4stlyhm3pkptxitznaip66qf3tnuhujabwq6louhibhds7lwk7qcoeyd.onion
senza chiave: 000
con la chiave: 200
```

Come leggerlo:

- **`000`** è il codice che `curl` restituisce quando la richiesta non arriva a
  destinazione: il client senza chiave non riesce a costruire la connessione.
- **`200`** dopo aver installato la chiave nella configurazione del client: stesso
  servizio, stesso indirizzo, stesso momento.
- L'indirizzo cambia a ogni esecuzione, perché il servizio ristretto viene creato da zero.

## Come funziona, in breve

1. Si crea un **secondo** onion service sul nodo `009h`, in `hs_ristretto`, senza toccare
   quello ordinario della rete, e si genera una coppia X25519 per il client.
2. La parte **pubblica** va nel servizio, in
   `<HiddenServiceDir>/authorized_clients/alice.auth`, nella forma
   `descriptor:x25519:<chiave in base32>`.
3. La parte **privata** va nel client, in un file `.auth_private` dentro
   `ClientOnionAuthDir`, nella forma `<indirizzo>:descriptor:x25519:<chiave>`.
4. Un `HUP` al servizio, che ripubblica il descrittore: da quel momento lo strato interno
   è cifrato con una chiave derivata dalle chiavi dei client autorizzati.

## Due trappole che mi sono costate tempo

**Il percorso del container.** `ClientOnionAuthDir` va scritto con il percorso **interno
al container**, non con quello dell'host. Con il percorso sbagliato tor non parte
affatto: esce con un errore di configurazione, e la prima volta mi sono ritrovato il
client del laboratorio morto senza capire perché. Lo script ricava il percorso interno
dal `DataDirectory` del nodo.

**La cartella vuota può disattivare la protezione.** La sola presenza
di `authorized_clients/` **non** abilita l'autorizzazione: nel codice di
tor 0.4.9.13 la lista dei client deve contenere almeno una chiave
valida. Se la cartella è vuota, oppure tutte le chiavi sono malformate,
l'autorizzazione risulta disabilitata e il servizio **può essere
raggiungibile da chiunque conosca l'indirizzo**. Tor inserisce comunque
voci `auth-client` fittizie nel descrittore per ragioni di formato;
non è corretto affermare che l'HSDir debba rifiutare il documento per
mancanza di file `.auth`. Una risposta `400 Invalid HS descriptor`
osservata in una vecchia sessione può avere un'altra causa.

**Non eliminare l'unica chiave autorizzata su un servizio reale**,
e non usare una cartella vuota come metodo di revoca. Configura e
verifica prima almeno un'altra credenziale, quindi rimuovi quella da
revocare e riavvia il processo tor secondo le istruzioni Tor Project.
Per sicurezza verifica poi l'accesso sia da un client autorizzato
sia da uno senza credenziale: quest'ultimo deve fallire.

Il laboratorio opera su una rete privata sacrificabile. Dopo un
esperimento interrotto, prima di recuperare un servizio, controlla
anche i log e la configurazione effettiva, invece di cancellare alla
cieca una directory che potrebbe contenere chiavi da conservare.

## Verifica automatica

Il controllo `lab13` verifica le due righe: `000` senza chiave, `200` con la chiave.

## Problemi noti

| Sintomo | Causa |
|---|---|
| Entrambe le prove danno `000` | il servizio non ha ripubblicato: attendi, gli HSDir hanno bisogno di qualche decina di secondi |
| Il client del laboratorio muore | percorso dell'host in `ClientOnionAuthDir` (vedi sopra) |
| `400 Invalid HS descriptor` nei log di `009h` | Errore di pubblicazione da diagnosticare nei log: una directory `authorized_clients` vuota, da sola, **non** dimostra questa causa. |
