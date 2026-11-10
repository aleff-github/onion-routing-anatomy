# Installazione

Da zero, su una macchina che non ha mai visto questo repository.

## Che cosa serve

| | Perché | Come si controlla |
|---|---|---|
| **Docker** | la rete di laboratorio gira tutta lì dentro; serve anche per compilare il libro | `docker run --rm hello-world` |
| **Python 3.11+** | il client didattico `torlab` | `python3 --version` |
| **`cryptography`** | X25519, Ed25519, AES | `python3 -c "import cryptography; print(cryptography.__version__)"` |
| **`pytest`** | test Python del client, da verificare eseguendoli | `python3 -m pytest --version` |
| **Rust (`cargo`)** | **solo** per il Laboratorio 20, che compila Arti | `cargo --version` |

```bash
python3 -m pip install -r requirements.txt
```

`stem` **non** serve sull'host: i tre laboratori che la usano (11, 16, 18) girano dentro
il container, che la include già.

Spazio su disco: circa 3 GB fra immagine Docker, sorgenti di tor e stato della rete.
Il Laboratorio 20 ne chiede altri 2 per compilare Arti.

Sistema: sviluppato e verificato su Linux. Su macOS Docker gira in una macchina
virtuale e `--network host` non funziona come su Linux: la rete di laboratorio va
adattata, e i laboratori che catturano traffico su `lo` (10 e 12) non funzionano.

## Passo 1: l'immagine

```bash
make -C labs/it/laboratorio immagine
```

Compila `tor` 0.4.9.13 dai sorgenti dentro l'immagine, insieme a Chutney, obfs4proxy,
snowflake-client, `tshark` e `curl`. **Richiede parecchi minuti** (sulla macchina su cui
è stato verificato, circa tredici partendo senza alcuna cache) e scarica qualche
centinaio di MB.

Perché compilarlo invece di installare il pacchetto della distribuzione:

- la versione è **fissata** nel Dockerfile (`ARG TOR_VERSION`), così i risultati del libro
  restano riproducibili anche fra due anni;
- serve `--enable-gpl`, senza cui manca il modulo della prova di lavoro degli onion
  service (Laboratorio 9, capitolo 15). I pacchetti delle distribuzioni di solito non
  lo attivano, perché cambierebbe la licenza del binario;
- avere i sorgenti a portata di mano è metà del libro: quando una domanda non ha risposta
  nelle specifiche, la risposta è in `src/core/or/`.

Controllo:

```bash
docker run --rm torlibro-lab:latest tor --version
```

## Passo 2: la rete

```bash
make -C labs/it/laboratorio avvia
```

Crea il container `torlibro-rete`, genera le chiavi e le configurazioni dei dieci nodi
con Chutney e attende il bootstrap. Circa due minuti: le autorità della rete privata
votano ogni 20 secondi, quindi il primo consenso arriva in fretta.

```bash
make -C labs/it/laboratorio verifica
```

Atteso: `successes:4 failures:0`. Chutney fa passare del traffico di prova attraverso la
rete e controlla che arrivi a destinazione.

Se qualcosa va storto, la pagina [Risoluzione dei problemi](Risoluzione-dei-problemi.md)
elenca i guasti che capitano davvero.

## Passo 3: tutto il resto

```bash
make -C labs/it test         # test Python offline
make -C labs/it/laboratorio verifica # verifica Chutney della rete avviata
```

I test Python e i controlli Chutney non equivalgono all'esecuzione integrale dei venti laboratori. Gli esperimenti richiedono anche gli script specifici della wiki; i laboratori 7, 15 e 19 necessitano dei dati storici pubblici. Il target `make verifica-lab` esegue ulteriori controlli, ma i diversi comandi non sono intercambiabili.

I test del codice, che non richiedono la rete:

```bash
PYTHONPATH=labs/it/codice python3 -m pytest -q labs/it/codice/torlab/test
```

## Passo 4 (facoltativo): il libro

```bash
make book-pdf     # compila book/it/anatomia-di-tor_it_A4.pdf con LaTeX dentro Docker
```

Non serve installare LaTeX: viene usata l'immagine `texlive/texlive`. La prima volta
scarica circa 5 GB.

## Fermare tutto

```bash
make -C labs/it/laboratorio ferma      # ferma i nodi, conserva chiavi e dati
make -C labs/it/laboratorio pulisci    # ferma e cancella labs/it/laboratorio/net/
```

`labs/it/laboratorio/net/` contiene le chiavi private dei nodi di prova. Non è versionata, e non va
pubblicata: sono chiavi di una rete giocattolo, ma prendere l'abitudine sbagliata con le
chiavi è un ottimo modo per pubblicarne una vera per sbaglio.
