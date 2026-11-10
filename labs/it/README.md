# Ambiente dei laboratori — Italiano

Questa cartella contiene l'ambiente didattico italiano completo:

- `laboratorio/` — rete Tor privata, script dei laboratori e Docker;
- `codice/` — client didattico `torlab`, test e dati riproducibili;
- `wiki/` — documentazione dei Laboratori 1–20.

È la versione italiana canonica dell'ambiente. L'edizione inglese vive separatamente in `../en/` e usa nomi, commenti, messaggi e output in inglese.

Dalla radice della repository usa `make -C labs/it test` per i test del codice e `make -C labs/it avvia` / `make -C labs/it verifica` per la rete privata italiana.
