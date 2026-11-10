# Security · Sicurezza

[English](#english) · [Italiano](#italiano)

## English

### What to report here

- Vulnerabilities in the code of this repository: `torlab` and the other laboratory code in
  `labs/`, the scripts in `scripts/`, the Docker image and the private-network setup.
- Problems that could expose a reader's data or system when following the laboratories — for
  example a listener that is not bound to 127.0.0.1, or an instruction that would make an
  experiment leave the private network.
- Errors in the book that could lead readers into an unsafe practice, if you prefer not to
  discuss them in public. Ordinary technical errors go through the
  [technical correction form](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=03-technical-correction.yml).

**Not here:** vulnerabilities in tor, Arti, the Tor specifications or Tor Project
infrastructure. This project is independent; report those to the Tor Project, which asks for
security issues to be sent to `security@torproject.org` (see
<https://www.torproject.org/contact/>).

### How to report privately

Do not open a public issue. Use GitHub's private vulnerability reporting: on the repository
page, open the **Security** tab and choose **Report a vulnerability**. Only you and the
maintainer see the report.

> GitHub offers this channel only on public repositories, and the owner has to enable it.
> If the button is missing, open a public issue that says only that you need a private
> contact — no details — and you will be contacted.

Please include what is affected (file, commit or release), how to reproduce it on the private
network, and the impact you expect. Do not include private keys, node identities from
`labs/*/lab/net/`, traffic captures or other people's data.

### What happens next

This is a book project maintained by one person, not a commercial product: there is no bug
bounty and no guaranteed response time. Reports are acknowledged as soon as possible, fixed
in the repository, and credited in the changelog and in [CONTRIBUTORS.md](CONTRIBUTORS.md)
unless you prefer otherwise. Please allow time for a fix before any public disclosure.

### Research safety

Never test against the public Tor network or its users. Everything in this project is meant
to run on the private network described in `labs/`.

---

## Italiano

### Che cosa segnalare qui

- Vulnerabilità nel codice di questa repository: `torlab` e il resto del codice dei
  laboratori in `labs/`, gli script in `scripts/`, l'immagine Docker e la configurazione della
  rete privata.
- Problemi che potrebbero esporre i dati o il sistema di chi segue i laboratori — per esempio
  un servizio in ascolto non limitato a 127.0.0.1, o un'istruzione che farebbe uscire un
  esperimento dalla rete privata.
- Errori del libro che potrebbero indurre a una pratica non sicura, se preferisci non
  discuterne in pubblico. Gli errori tecnici ordinari si segnalano con il
  [modulo di correzione tecnica](https://github.com/aleff-github/onion-routing-anatomy/issues/new?template=03-technical-correction.yml).

**Non qui:** vulnerabilità di tor, Arti, delle specifiche di Tor o dell'infrastruttura del Tor
Project. Questo progetto è indipendente: vanno segnalate al Tor Project, che chiede di inviare
i problemi di sicurezza a `security@torproject.org` (vedi <https://www.torproject.org/contact/>).

### Come segnalare in privato

Non aprire una issue pubblica. Usa la segnalazione privata delle vulnerabilità di GitHub:
nella pagina della repository apri la scheda **Security** e scegli **Report a
vulnerability**. La segnalazione è visibile solo a te e a chi mantiene il progetto.

> GitHub offre questo canale solo per le repository pubbliche, e il proprietario deve
> attivarlo. Se il pulsante manca, apri una issue pubblica che dica soltanto che ti serve un
> contatto privato, senza dettagli: sarai contattato.

Indica che cosa è coinvolto (file, commit o release), come riprodurre il problema sulla rete
privata e l'impatto che ti aspetti. Non inserire chiavi private, identità dei nodi di
`labs/*/lab/net/`, catture di traffico o dati di altre persone.

### Che cosa succede dopo

È il progetto di un libro mantenuto da una persona, non un prodotto commerciale: non ci sono
ricompense né tempi di risposta garantiti. Le segnalazioni ricevono risposta appena possibile,
vengono corrette nella repository e riconosciute nel changelog e in
[CONTRIBUTORS.md](CONTRIBUTORS.md), salvo diversa preferenza. Lascia il tempo di correggere
prima di rendere pubblico il problema.

### Sicurezza della ricerca

Non fare mai prove contro la rete Tor pubblica o i suoi utenti. Tutto in questo progetto è
pensato per la rete privata descritta in `labs/`.
