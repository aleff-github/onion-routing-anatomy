# Historical public research data

Laboratories **7, 15 and 19** reproduce calculations against an archived Tor
microdescriptor consensus. The private Chutney consensus committed as a test
fixture is **not** a substitute for the public snapshot used in the book.

From the repository root run:

```bash
make -C labs/en data
```

This on-demand script fetches the Tor Project CollecTor September 2026 archive
and extracts `2026-09-23-15-00-00-consensus-microdesc` into
`labs/en/data/collector/consensus-microdesc-2026-09-23-15`.
It validates the document's *format header*, but does **not** authenticate its
signatures or independently guarantee the historical calculations. Those
checks require the appropriate authority certificates and actual test runs.

The download uses ordinary HTTPS only; the laboratory does not probe
public Tor relays. The generated snapshot is ignored by Git. Download,
decompression and numerical reproduction have **not** been executed here.
