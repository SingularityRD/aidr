---
"@singularityrd/aidr-core": minor
"@singularityrd/aidr-cli": minor
---

The installer download portal carries several formats per platform (Windows `.msi`; Linux `.deb`, `.rpm` and `.tar.gz`). The signed installer catalog gains `schema_version` 2 (one file per platform and format); schema 1 catalogs still verify and parse, and the publisher keeps writing schema 1 when every platform has a single file. `aidr update` now picks the installer that matches how the machine was installed (MSI, dpkg, rpm or tarball) and refuses only when the catalog has no installer in that format, listing the formats it does offer.
