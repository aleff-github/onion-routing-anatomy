# Guida di stile

## Voce e tono
- Italiano chiaro e preciso; frasi brevi; registro da manuale universitario, non da blog.
- Si usa il "noi" didattico ("vediamo ora come..."); ci si rivolge al lettore con il "tu" solo negli esercizi e nei laboratori.
- Ogni concetto nuovo: **motivazione → meccanismo → dettaglio a basso livello → esempio concreto**.
- Niente enfasi vuota ("rivoluzionario", "incredibile"). Niente sensazionalismo su dark web o criminalità.

## Struttura di un capitolo
1. `\chapter{}` + `\aggiornatoal{data}{versioni}`
2. Riquadro `obiettivi` (cosa saprà fare il lettore).
3. Sezioni; figure dove un diagramma chiarisce un meccanismo.
4. Riquadri: `approfondimento` (dettagli opzionali), `attenzione` (errori comuni/sicurezza), `storia` (aneddoti storici), `spec` (citazione/riferimento a torspec).
5. `laboratorio` (Parte II–III).
6. `\section*{Riepilogo}` in punti.
7. `\section*{Esercizi}` con `\begin{esercizio}[difficoltà]` (1–3 stelle), soluzioni in App. D (`\begin{soluzione}{etichetta}`).
8. `\section*{Per approfondire}`: letture commentate.

## Convenzioni tipografiche
- Nomi di celle/comandi di protocollo: `\cella{CREATE2}`, `\cella{RELAY\_BEGIN}`.
- Opzioni torrc, file, comandi: `\opt{SocksPort}`, `\file{/etc/tor/torrc}`, `\cmd{tor --verify-config}`.
- Valori esadecimali: `0x0A`; lunghezze in byte esplicite ("4 byte", non "4B").
- Numeri: separatore decimale virgola, migliaia punto (`\num{}` di siunitx).
- Formati binari: figura TikZ a campi con offset e lunghezze, sul modello di `source/it/figure/fig08-cella-fissa.tex`, oppure tabella campo/byte/contenuto per i formati semplici.
- Termini inglesi alla prima occorrenza: corsivo + traduzione tra parentesi, poi secondo `terminologia.md`.
- Citazioni: `\cite{}` per articoli; `\spec{tor-spec}{sezione}` per le specifiche; i titoli di opere (articoli, proposte, libri) sempre con `\titolo{}`.

## Figure
- TikZ, stile comune definito in `macro.tex` (`nodo relay`, `nodo client`, `freccia cella`, colori `torviola`, `torverde`...).
- Didascalie complete, comprensibili senza leggere il testo.
- Diagrammi di sequenza per handshake; diagrammi a strati per la cifratura; tabelle a campi per i formati.
