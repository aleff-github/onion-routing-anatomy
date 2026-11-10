# Book editions and review copies

| Language | Folder | Status |
|---|---|---|
| Italiano | [`it/`](it/) — PDF A4, EPUB 3, PDF 7×10 and cover | **Official Italian original, version 1.0.0** |
| English | [`en/`](en/) | AI-generated translation; PDF/EPUB review copies can be built, not independently validated |
| Español | [`es/`](es/) | Traducción generada con IA; archivos de revisión, sin validación lingüística independiente |
| Русский | [`ru/`](ru/) | Черновой перевод, независимая языковая проверка не выполнена |
| 简体中文 | [`zh-Hans/`](zh-Hans/) | AI 生成的译稿，尚未经过独立语言审校 |

The source for each edition is in [`source/<language>/`](../source/). The four translated folders contain localized status READMEs and generated
PDF/EPUB/cover **review copies**. Their presence does not imply an independent
linguistic or scientific review, or an official translated release.

From the repository root:

```sh
make book                             # only the official Italian edition
make book-traduzione LINGUA=en         # one translated PDF A4, EPUB and cover
make book-traduzioni                  # all four translated review copies
make composizione LINGUE="en es ru zh-Hans"
make epub-check LINGUE="en es ru zh-Hans"
```

The translation build targets use the existing per-language Makefiles (locally if
LuaLaTeX is installed, otherwise via the root Docker-based TeX Live setup).
The output is copied to `book/<language>/` with language-specific filenames. Existing
review copies can be examined and corrected independently; generating or storing them
does **not** add them to an official release.

**Release boundary:** `make release-package` and `make release-check` still operate
only on `book/it/` for `v1.0.0-it`. English, Spanish, Russian and Simplified Chinese do
not belong to that release. For their status and outstanding reviews, see
[translation review](../docs/translation-review.md) and [language notes](../docs/translations/).

The Italian edition is distributed free of charge under
[GPL-3.0-or-later](../LICENSE). Release file descriptions and checksum
information are in the [Italian release notes](../docs/releases/v1.0.0-it.md).
