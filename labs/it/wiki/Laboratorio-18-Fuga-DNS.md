# Laboratorio 18 — tor riconosce un indizio di rischio DNS

| | |
|---|---|
| **Capitolo** | 28 — Errori di chi usa Tor |
| **Serve la rete?** | sì |
| **Prerequisiti** | la rete avviata |
| **Tempo** | 1 ora |
| **File** | `labs/it/laboratorio/fuga_dns.py` |

## Che cosa dimostra

L'errore più comune di chi usa Tor a mano: far risolvere i nomi **all'applicazione**
invece che alla rete. La connessione passa da Tor, quindi sembra tutto a posto, ma una query DNS potrebbe essere già uscita dal circuito. Non è però certo: l'applicazione potrebbe usare cache, file locali, DNS cifrato o un indirizzo IP letterale. L'avviso di Tor indica il formato della richiesta SOCKS, non prova che sia avvenuta una fuga.

Tor può **segnalare il comportamento potenzialmente rischioso** quando è configurato per farlo.

## Preparazione

```bash
make -C labs/it/laboratorio avvia
```

Lo script avvia già un server HTTP locale di prova e gira dentro il container, perché usa `stem` per leggere gli avvisi dalla porta di controllo:

```bash
docker exec -w /tmp torlibro-rete python3 /lab/fuga_dns.py
```

## Output atteso

```
--socks5           HTTP 200  tor: Your application (using socks5 to port 8080) is giving
                             Tor only an IP address. Applications that do DNS resolves
                             themselves may leak information.
--socks5-hostname  HTTP 200  tor: Your application (using socks5 to port 8080) instructed
                             Tor to take care of the DNS resolution itself if necessary.
--socks5 SafeSocks HTTP 000
```

Come leggerlo:

- **`--socks5`**: `curl` risolve il nome da sé e passa a tor **solo un indirizzo IP**. La
  richiesta funziona (`200`), ed è proprio questo il problema: nulla segnala all'utente
  che una richiesta SOCKS potenzialmente rischiosa è stata inviata. L'avviso lo produce tor grazie a `TestSocks 1`, che di norma non è attivo e che
  lo script accende per l'occasione dalla porta di controllo.
- **`--socks5-hostname`**: `curl` passa il **nome**, e la risoluzione avviene all'exit.
  È il comportamento corretto.
- **`SafeSocks 1`**: tor **rifiuta** la prima forma invece di limitarsi ad avvisare.
  `000` è ciò che `curl` riporta quando la connessione non si stabilisce.

Le due opzioni di `curl` differiscono per sette caratteri e hanno conseguenze opposte
sull'anonimato. È la ragione per cui la risposta corretta alla domanda «come uso Tor?»
è quasi sempre «Tor Browser», e non «configura il proxy».

> **Una precisazione onesta.** Il laboratorio usa `localhost`, che il sistema risolve in
> loopback **senza** interrogare alcun resolver: qui nessuna query DNS lascia davvero la
> macchina. Ciò che il laboratorio dimostra è il *meccanismo* — con `--socks5` l'applicazione
> risolve il nome da sé e passa a tor un indirizzo IP, e tor lo rileva. Con un dominio reale
> al posto di `localhost`, quella risoluzione potrebbe produrre una query esterna, in chiaro o cifrata secondo la configurazione DNS. Per questo manteniamo l'esperimento nella rete privata.

## Chi risolve `localhost` all'exit

Con `--socks5-hostname` il nome arriva all'exit, che lo risolve con il resolver indicato da
`ServerDNSResolvConfFile`. Nella rete del libro è `labs/it/laboratorio/dns_locale.conf`, che punta a
un resolver minimo della rete stessa, `labs/it/laboratorio/dns_locale.py`: ascolta solo su
`127.0.0.1:5300` (UDP), risponde `127.0.0.1` per `localhost` e «nome inesistente»
(NXDOMAIN) per tutto il resto, e non inoltra nulla ad altri resolver. Così l'esperimento non
dipende dal DNS della macchina: alcuni resolver rispondono NXDOMAIN anche a `localhost`, e
con il resolver di sistema il secondo caso falliva.

Il resolver è attivo solo mentre gira `fuga_dns.py`, che all'avvio fa rileggere agli exit
la configurazione (aggiorna la data di `dns_locale.conf` e manda `SIGHUP` ai soli exit) e
alla fine stampa su stderr le domande ricevute:

```
dns locale: localhost A 127.0.0.1
```

Se la prova viene ripetuta entro qualche minuto la riga può mancare: l'exit risponde dalla
propria cache, che tor conserva almeno 5 minuti qualunque sia il TTL (difesa contro gli
attacchi «DefectTor», `clip_dns_ttl` in `connection_edge.c`). Fuori dalla prova gli exit
non risolvono alcun nome: la rete usa solo indirizzi IP.

## Le tre opzioni di tor che contano

| Opzione | Effetto |
|---|---|
| `TestSocks 1` | annota nel log quale delle due forme ha visto. Serve a diagnosticare, non a proteggere |
| `SafeSocks 1` | rifiuta le connessioni che passano un indirizzo IP invece di un nome |
| `WarnUnsafeSocks` | avvisa (attiva per impostazione predefinita) |

Nessuna delle tre opzioni può impedire una query DNS già effettuata dall'applicazione: Tor può osservare solo il formato della richiesta SOCKS che riceve. Lo script usa `--noproxy ''` per impedire che la variabile `NO_PROXY` aggiri il proxy quando la destinazione è `localhost`.

## Verifica automatica

Il controllo `lab18` è predisposto per verificare le tre situazioni; i risultati qui citati sono esempi di riferimento e non nuove esecuzioni.

## Problemi noti

| Sintomo | Causa |
|---|---|
| Nessun avviso | lo script attiva `TestSocks` dalla porta di controllo (`SETCONF`): se la connessione al controllo fallisce, non attiva nulla |
| Anche la terza prova dà `200` | `SafeSocks` non è stato applicato: controlla che `set_options` non abbia sollevato un errore |
| `HTTP 000` in tutte e tre | server locale o rete privata non disponibili; lo script avvia da sé il server di prova sulla porta 8080 |
| Solo `--socks5-hostname` dà `000` | il resolver locale non è partito (porta `127.0.0.1:5300` occupata: lo script si ferma con un errore esplicito) oppure la rete è stata creata prima del 28/10/2026 e gli exit usano ancora `/etc/resolv.conf`: `python3 scripts/loopback_network.py controlla` |
