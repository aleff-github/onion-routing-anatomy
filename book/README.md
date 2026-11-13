# Book editions · Edizioni del libro

All five language editions of *Anatomia di Tor* (version 1.0.0) are available to read and download free of charge.

| Language | PDF A4 | EPUB 3 | Cover | Zenodo |
|---|---|---|---|
| Italiano (original) | [PDF](it/anatomia-di-tor_it_A4.pdf) | [EPUB](it/anatomia-di-tor_it.epub) | [Cover](it/anatomia-di-tor_it_copertina.png) | [DOI](https://doi.org/10.5281/zenodo.24207180) |
| English | [PDF](./en/anatomy-of-tor_en_A4.pdf) | [EPUB](./en/anatomy-of-tor_en.epub) | [Cover](./en/anatomy-of-tor_en_cover.png) | [DOI](https://doi.org/10.5281/zenodo.24207675) |
| Español | [PDF](./es/anatomía-de-tor_es_A4.pdf) | [EPUB](./es/anatomía-de-tor_es.epub) | [Cover](./es/anatomía-de-tor_es_portada.png) | [DOI](https://doi.org/10.5281/zenodo.24207811) |
| Русский | [PDF](./ru/анатомия-tor_ru_A4.pdf) | [EPUB](./ru/анатомия-tor_ru.epub) | [Cover](./ru/анатомия-tor_ru_обложка.png) | [DOI](https://doi.org/10.5281/zenodo.24207874) |
| 简体中文 | [PDF](./zh-Hans/tor-解剖_zh-Hans_A4.pdf) | [EPUB](./zh-Hans/tor-解剖_zh-Hans.epub) | [Cover](./zh-Hans/tor-解剖_zh-Hans_封面.png) | [DOI](https://doi.org/10.5281/zenodo.24207976) |

The Italian original also offers a [7×10-inch print PDF](it/anatomia-di-tor_it_7x10.pdf) and its [GitHub release `v1.0.0-it`](https://github.com/aleff-github/onion-routing-anatomy/releases/tag/v1.0.0-it).

**Important: translation status.** The English, Spanish, Russian and Simplified Chinese editions were generated with AI tools. While structural, PDF-layout and EPUB checks were documented, they **have not undergone an independent linguistic review by native speakers** or an independent scientific review. Errors of translation, meaning and terminology may remain. The Italian original is the authoritative reference. Publication here does not imply such independent validation.

**Avvertenza sulle traduzioni.** Le quattro traduzioni sono pubblicate gratuitamente ma **non sono state sottoposte a revisione linguistica indipendente da parte di madrelingua**. In caso di divergenze fa fede il testo originale italiano.

All five editions have dedicated GitHub releases: [Italian](https://github.com/aleff-github/onion-routing-anatomy/releases/tag/v1.0.0-it) · [English](https://github.com/aleff-github/onion-routing-anatomy/releases/tag/v1.0.0-en) · [Spanish](https://github.com/aleff-github/onion-routing-anatomy/releases/tag/v1.0.0-es) · [Russian](https://github.com/aleff-github/onion-routing-anatomy/releases/tag/v1.0.0-ru) · [Simplified Chinese](https://github.com/aleff-github/onion-routing-anatomy/releases/tag/v1.0.0-zh-Hans). The Italian release contains only the original, and the four translated releases contain their own PDF, EPUB, cover and checksums.

All editions and their corresponding sources in [`source/`](../source/) are distributed under [GPL-3.0-or-later](../LICENSE). Translation status: [language notes](../docs/translations/) · [participate in review](../docs/translation-review.md).

## Rebuild

```sh
make book                       # Italian PDF, EPUB and cover
make book-traduzione LINGUA=en   # One translated edition (en, es, ru, zh-Hans)
make book-traduzioni            # All four translated editions
make composizione LINGUE="en es ru zh-Hans"
make epub-check LINGUE="en es ru zh-Hans"
```

The build targets generate the same formats from localized LaTeX sources. A successful build is a technical check, not independent linguistic validation.
