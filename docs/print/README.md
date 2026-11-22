# Edizioni cartacee 7×10, versione 1.0.0

Le configurazioni cartacee riutilizzano i capitoli, le traduzioni, le figure,
le formule, la bibliografia e le macro dell'edizione digitale. Le uniche
impostazioni comuni aggiunte sono in `source/shared/print/layout.tex`, caricato
esclusivamente dai cinque punti d'ingresso di stampa.

| Lingua | Punto d'ingresso | PDF locale |
|---|---|---|
| it | `source/it/stampa.tex` | `book/it/anatomia-di-tor_it_7x10.pdf` |
| en | `source/en/print.tex` | `book/en/anatomy-of-tor_en_7x10.pdf` |
| es | `source/es/impresion.tex` | `book/es/anatomía-de-tor_es_7x10.pdf` |
| ru | `source/ru/печать.tex` | `book/ru/анатомия-tor_ru_7x10.pdf` |
| zh-Hans | `source/zh-Hans/印刷.tex` | `book/zh-Hans/tor-解剖_zh-Hans_7x10.pdf` |

## Compilazione locale

Servono Python 3 e LuaLaTeX, latexmk, biber, makeindex con i pacchetti/font dei
preamboli originali. In assenza di `latexmk` locale viene usata l'immagine Docker
indicata da `IMMAGINE`, da scaricare esplicitamente prima della compilazione.
I container hanno rete disabilitata e limiti di 2 CPU e 6 GiB ciascuno. Non sono
necessari servizi esterni, API commerciali o GitHub Actions.

```sh
docker info
docker pull texlive/texlive@sha256:07e8062637249c4f780ca59f42cc2ed592bc2dc1db4320769406aee3f98aa70e
make book-print LINGUA=en
make book-print-all IMMAGINE=texlive/texlive@sha256:07e8062637249c4f780ca59f42cc2ed592bc2dc1db4320769406aee3f98aa70e
# Sono disponibili anche: make -C source/en print, e analoghi per es/ru/zh-Hans.
```

Per riprodurre l'ambiente della verifica usare il digest Docker riportato nel
comando precedente: il tag `latest` è mobile. `SOURCE_DATE_EPOCH` viene fissato per
le sole compilazioni cartacee. Log, comando e immagine effettiva sono registrati
in `build/print-audit/<lingua>-build.{log,json}`.

I sorgenti vengono copiati in `build/print-work/<lingua>/source/`: ogni lingua ha
il proprio albero isolato. Le copie escludono gli ausiliari digitali e `solo.tex`.
Le modifiche devono essere fatte ai sorgenti sotto `source/`, mai alle copie di
build. I PDF finali vengono copiati in `book/` solo dopo il successo di latexmk.
I nuovi PDF 7×10 vengono tracciati esplicitamente solo dopo una compilazione e
validazione riuscita; la rigenerazione locale non implica automaticamente
l'approvazione di una nuova versione. L'italiano già distribuito resta
invariato in questa integrazione.

## Validazione e rendering

```sh
python3 -m venv build/print-venv
build/print-venv/bin/pip install -r scripts/requirements-print.txt
make print-check PRINT_PYTHON=build/print-venv/bin/python
make print-render PRINT_PYTHON=build/print-venv/bin/python
# Per una sola lingua: aggiungere PRINT_LANGUAGES=en
python3 scripts/check_print_regression.py
make check
```

È necessario `pdffonts` da Poppler. Ogni pagina viene analizzata e rasterizzata;
con `--render` vengono salvati i PNG a 100 dpi e i provini da 16 pagine. I report
JSON riportano anche dimensioni, hash, font, pagine bianche, glifi mancanti,
coordinate sospette, avvisi LaTeX e frammenti di codice non ritrovati nel testo.
Gli hash degli input registrati nella build devono corrispondere ai sorgenti attuali.
`print-check` esegue anche il confronto per sezioni con gli A4 e il controllo delle
regressioni digitali. La punteggiatura CJK sospetta viene controllata misurando
l’inchiostro a 288 dpi, con entrambe le coordinate conservate nel report.
Un esito `REVIEW` o `FAIL` restituisce un codice diverso da zero. Nessun controllo
automatico equivale a un'approvazione visiva o editoriale.

I confronti testuali con A4 hanno limiti: legature, sillabazione, ordine di lettura
di tabelle/formule, testatine e numeri nell'indice cambiano. I token mancanti sono
un elenco diagnostico da esaminare, non una prova automatica di testo eliminato.
I controlli dei listati ignorano gli spazi, quindi non certificano l'indentazione.
Le verifiche delle coordinate non possono dimostrare da sole l'assenza di ogni
sovrapposizione o di un errore interno a un diagramma. Il registro delle ispezioni
visive deve riportare il PDF esaminato (SHA-256), le pagine, la scala e i limiti.

```sh
make print-clean
```

La pulizia elimina solo gli alberi `build/print-work`, preservando PDF, evidenze e
cache. Non eseguire la pulizia durante una compilazione o prima di una verifica
che richieda i log. I comandi digitali preesistenti restano disponibili.

## Geometria del formato 7×10

Il formato è di 504 × 720 pt (7 × 10 pollici), con pagine singole
fronte-retro e senza vivo. Margine interno 1″, esterno 0,53″
(compresa una riserva ottica di 0,03″ per i corsivi), superiore e
inferiore 0,75″. Il validatore segnala i volumi oltre 400 pagine,
per cui la rilegatura richiederebbe una nuova valutazione dei margini.

Colori, font, formule e contenuti restano quelli del progetto.
Le tabelle multipagina mantengono la loro struttura. Questa è una
variante d'impaginazione: non implica servizi di stampa, vendita,
ISBN o copertine complete.

Le nuove edizioni 7×10 sono distribuite accanto alle edizioni A4 ed EPUB
preesistenti, senza modificare le release GitHub già pubblicate.
