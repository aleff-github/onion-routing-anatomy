# Originalità e diritto d'autore (regole vincolanti)

Il libro deve essere un'opera originale. Queste regole valgono per ogni capitolo.

## Cosa si può usare liberamente
- **Fatti tecnici**: valori, formati, costanti, nomi dei campi, algoritmi. I fatti non sono tutelati
  dal diritto d'autore; lo è solo il modo in cui un testo li esprime.
- **Nomi** di comandi, campi, proposte, software.

## Come si scrive
1. **Mai tradurre passaggi**: né dalle specifiche né da articoli o libri. Si legge la fonte, si capisce
   il meccanismo, si chiude la fonte e si spiega con parole, ordine ed esempi propri.
   Una traduzione fedele è un'opera derivata anche se è in un'altra lingua.
2. **Struttura propria**: l'ordine degli argomenti, le analogie, gli esempi numerici, gli esercizi
   e le figure si ideano da zero, non seguendo la scaletta di un altro testo.
3. **Citazioni testuali** (art. 70 L. 633/1941: citazione per critica, discussione o insegnamento):
   solo brevi, solo se servono davvero, sempre tra virgolette `\enquote{}`, con fonte e, se tradotte,
   la dicitura "(trad. nostra)". Massimo una o due frasi per citazione, poche per capitolo.
4. **Tabelle di valori** (comandi, codici): i dati sono fatti, ma la tabella va rielaborata
   (colonne, raggruppamenti, descrizioni proprie in italiano) e la fonte citata nella didascalia o nel testo.
5. **Figure**: sempre disegnate da noi. Nessuna figura riprodotta o ricalcata da altri testi, articoli o
   siti (incluso il Tor Project) senza licenza compatibile e attribuzione. Loghi: mai.
6. **Codice**: scritto da noi. Estratti dal codice di tor (licenza BSD a 3 clausole) o Arti
   (MIT/Apache-2.0) solo brevi, con percorso del file, versione e nota di licenza.
7. **Altri libri su Tor** (in qualsiasi lingua): non si usano come fonte per la stesura; se si citano, solo
   per un'idea specifica, con riferimento bibliografico.

## Controlli
- `make originalita`: cerca sequenze di 8 parole identiche tra il libro e `fonti/`.
  Per confrontare il libro con altri testi (es. libri o tesi italiane su Tor), metterne una copia in formato
  testo in `fonti/confronto/` (non versionata). Se il corpus manca o non contiene testi sufficienti,
  il controllo termina con codice **2** («non eseguito»), non con un falso risultato positivo.
  Codice **1** indica sequenze da esaminare; codice **0** indica che non sono state trovate
  coincidenze *nei soli documenti forniti*, non certifica l'originalità del libro.
- Il controllo automatico non rileva le traduzioni: per queste vale la regola 1, verificata in revisione.
- Il controllo ammette due categorie di coincidenze, contandole a parte perché restino visibili:
  le sequenze fatte in maggioranza di numeri (indirizzi, porte, articoli di legge: coincidono
  per forza) e le citazioni letterali elencate in `scripts/data/literal-quotations.txt`, che sono
  denominazioni e formule di norme italiane. Una norma va citata con le parole del legislatore:
  riscriverla sarebbe un errore, non un merito. Ogni riga di quel file porta il proprio motivo, e
  l'elenco va tenuto corto.
- Il controllo non esamina `source/it/figure/` (le etichette dei diagrammi riportano dati di protocollo) e ignora i listati (`lstlisting`), gli URL, le formule matematiche i titoli in `\emph{}` seguiti da `\cite` quelli marcati con `\titolo{}` e i nomi di sezione nei riferimenti `\spec{}{}` (da usare per ogni titolo di opera citata), che contengono output di programmi e indirizzi: il codice nei listati va quindi verificato a mano secondo la regola 6.
- Prima della pubblicazione: verifica con un servizio antiplagio professionale sul PDF finale
  e revisione del contratto editoriale/licenze da parte di un legale.
