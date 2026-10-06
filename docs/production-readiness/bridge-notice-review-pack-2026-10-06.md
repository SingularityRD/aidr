# Bridge dependency notice review inputs — 6 October 2026

Status: **DRAFT / OPEN REVIEW INPUT / NOT ACCEPTED OR PUBLISHED**.
These actual source and runtime materials prepare COM-002 review. They grant no
exception, distribution permission, Legal approval or production acceptance.
The worktree is not an accepted signed release candidate. Preserve the source
snapshot and regenerate/bind materials after the final candidate is selected.

## Current source and runtime scope

### Latest Alpine runtime — 0 measured findings, acceptance OPEN

The latest bridge image is
`sha256:dd8993b9abaed977cc6d6a123a39388f188ba86d83552b140935773005b3d195`.
It uses the digest-pinned official Python 3.12.15 Alpine 3.24 base, the unchanged
30-package runtime lock and actual selected musllinux wheels. The exact source
wheel metadata now has SHA-256
`7f21cc59f321dac9a13865d1639f9cda20f092aea4a4cfb1f89de02a00645e4f`.
All 30 installed package metadata fields, 60 METADATA/WHEEL files, 36 physical
wheel licence texts and 12 native ELF payloads match the verified selected
wheels. Eight native wheel filenames differ from the preserved historical
manylinux selection; all 36 dist-info licence hashes remain equal.

The [new technical security report](./bridge-high-zero-security-2026-10-06.md)
records 0 findings at every scanned severity over 47 APK and 30 Python packages,
98 actual image tests without skips, TLS verification and four readiness-command
checks. Manual vendor source/version checks cover declared scanner database gaps.
This local evidence grants no Legal, Security, publisher or customer acceptance.

The [actual APK/native inventory](./evidence/bridge-high-zero-apk-native-inventory-2026-10-06.json)
replaces dpkg material for this image: 47 actual package/version/origin/licence
declarations, 46 observed native paths, four raw APK/repository records and 37
physical Python/CPython notice texts. None of the 47 APK packages contains an
installed physical licence/copyright text. Metadata declarations and historical
Debian notice texts do not fulfil the current container's complete notice scope.

The [Alpine source-material index](./evidence/bridge-high-zero-legal-source-inventory-2026-10-06.json)
now binds 252 exact checksum-verified source/patch/config/helper inputs, including
BusyBox 1.37.0-r31, binutils 2.45.1-r1 (also its with-gold source), and PostgreSQL
18.6/libpq. All 46 real APK packages map to 33 exact installed-origin recipes;
the empty `.python-rundeps` virtual row is explicit. The pack preserves 33
installed-origin source archives, all 15 declared lifecycle/trigger controls and
164 upstream licence/header materials (152 full texts and 12 explicitly labelled
header prefixes). BusyBox declares
GPL-2.0-only; exact binutils `objdump.c`/`ldmain.c` headers declare GPLv3-or-later,
which is retained alongside the APK's coarser mixed expression. PostgreSQL's
COPYRIGHT text is retained. The declared-material fetch gaps are closed;
whole-origin licence expressions remain raw metadata rather than an automatic
file/subpackage legal determination. Candidate utmps/skalibs recipes add ten
verified inputs and two archives. Stable BusyBox APK/control/binary bytes match
the image, but surviving vendor logs cannot establish the exact executed static
dependency build. That source-to-byte mapping remains an engineering gap.
No written offer or human distribution acceptance was issued.

The final pack is
`.tmp-test/high-zero-2026-10-06/bridge/legal-complete/full-declared-source-materials.tar.gz`,
317,367,132 bytes, SHA-256
`7dbadf8f83512ff0c6e653aec3c90e5a1e20cc4e031ebbe9ad6a06eb1a0066c9`;
its manifest binds 641 files. The initial 82 MB pack is immutable historical proof.

Three selected musllinux wheels additionally bundle distinct `libgcc_s` payloads
in cryptography, pydantic-core and watchfiles. Exact byte inventories are
preserved in the [wheel equality proof](./evidence/bridge-high-zero-wheel-equality-2026-10-06.json)
and prepared wheel licence materials. Their independent source version/terms
remain OPEN; equality of enclosing wheel licence texts is not GCC runtime
licence approval. The [publisher trace](./evidence/bridge-high-zero-libgcc-provenance-2026-10-06.json)
records cryptography's declared libgcc 14.2.0-r6 without source/hash/licence fields;
the two other wheel provenance endpoints return 404. APK GCC 15.2.0 source is
bundled for APK libraries and does not resolve those wheel-source mappings.
This new scope must be included in COM-002 review.

All Debian image bindings and materials below are preserved historical inputs.
Use the Alpine image and fresh evidence above for current runtime review.

### Earlier Debian repaired image — historical same-day proof

The earlier Debian Dockerfile added the PCRE2 security floor and removed the unused pip
installer plus ensurepip after the hash-locked runtime installation. The exact
repaired image is `sha256:1840809665e666eec7c89cc7fb451fa7b65210d37dcf7ee0a41f7eb82390386a`;
the unchanged runtime lock still contains 30 packages. Actual image tests passed
98/98 and its nonroot libpq TLS probe used `verify-full` successfully. This does
not establish full image vulnerability clearance or Legal acceptance.

Fresh collected inputs for this image are the [17 native library paths](./evidence/bridge-system-native-inventory-2026-10-06-current.json),
[embedded Rust/OpenSSL inventory](./evidence/bridge-cryptography-static-native-2026-10-06-current.json)
and [110 OS package/version/copyright records](./evidence/bridge-full-os-notice-inventory-2026-10-06-current.json).
All 110 package copyright files, 26 common licence texts and dpkg status were
saved and hash checked; 137 materials, no missing or unreadable entry. The
native collection also verified all 41 copied notice materials. These are
review inputs and still do not classify the complete container licence terms.

The [complete current security findings](./bridge-image-security-2026-10-06.md)
record 241 package/advisory rows, including 52 HIGH, with no available vendor
fix in the pinned scan database. Seven initially fixable rows were removed.
Security and Legal approval remain OPEN; no exception was granted.

### Earlier extraction preserved below

The earlier `f3e9e8…` image extraction and its references below are historical
same-day inputs. They are not the latest Dockerfile/image binding; use the
repaired image and current inventories above for new review.

The current runtime lock selects 30 official hash-verified Python wheels,
including pure `psycopg==3.2.10`. Its SHA-256 is
`af4cf84b33c07df728ddb2e8b9a0f10c1d4f8f309295cc18bf808b8377a5c598`.
[`pypi-runtime-licenses.json`](../../services/aig-bridge/pypi-runtime-licenses.json)
binds each selected wheel, metadata and licence-file digest to that lock.

The lockfile-derived CycloneDX snapshot has 216 components / 204 libraries:
202 permissive declarations, 2 review-required declarations and 0 UNKNOWN
declarations. The two review-required packages are certifi 2026.7.22 (MPL-2.0)
and psycopg 3.2.10 (LGPLv3). This is a package declaration inventory; it does not
classify the full container or establish its redistribution obligations.
The strict licence report intentionally exits 1 until real review is recorded.

The actual bridge runtime extraction uses the Python driver implementation;
the binary driver module is absent. The measured dependency set identifies
17 system-libpq library paths, their SHA-256 bytes, Debian owners and versions.
It includes `libpq5 17.11-0+deb13u1` and `libssl3t64 3.5.7-1~deb13u3`.
See the [scoped measured inventory](./evidence/bridge-system-native-inventory-2026-10-06.json).
This record excludes other OS packages, other containers, alternate platforms
and customer acceptance. The separately recorded security disposition is not
a full OS vulnerability clearance or a licence decision.

Separate from those 17 system-libpq paths, the current cryptography 50.0.2
Rust module statically embeds measured OpenSSL 4.0.3. The exact runtime module
hash matches the selected official SHA-locked wheel's module bytes. Its record
and exact tagged OpenSSL LICENSE/AUTHORS/README primary materials are preserved
in the tracked inventory and archive supplement. This does not classify every
Rust dependency, prove complete binary source provenance or grant approval.

The source runtime receipt binds that extraction to locally built image
`sha256:f3e9e8b6571b532e221ce27461b6fb09b735923eba7a771fcac70b52cb7d8a35`
and exact Dockerfile/runtime-lock/CI-lock/metadata hashes. Its reported source
and runtime-lock byte matches are recorded as local build evidence, not an
approved customer delivery. The receipt digest is
`094a39b86087682bc3d2094793949395ecb5a650efd73387bbbbad46ea3e2624`;
see the tracked inventory's `runtime_binding_receipt` reference.

## Review material archive

The local archive is
`.tmp-test/production-followup-2026-10-06/crypto-50.0.2-wheel-and-native-notice-review/`.
It contains actual texts, not blank licence templates:

| Material | Content and binding |
|---|---|
| `inventory.json` | Archive index, OPEN status, exact wheel/file hashes and scoped system inventory digest; SHA-256 `23c788b9bc2f57ccb9c1843a3e40aa13f9e9eaefebffadf422963ab33b6e6122` |
| `source-manifest.json`, `source-lock.txt` | Exact metadata/lock bytes used to prepare this archive |
| `wheels/` | 36 licence texts from all 30 selected wheel packages, with exact source member paths and text hashes |
| `native-runtime-inventory.json` | Source runtime extraction, SHA-256 `73078e38a5d057339775db8c0acb583a9fc46f4c577ff782d517d3b04cf5a461`, 17 library paths and notice attribution |
| `runtime-security-receipt.json` | Separately preserved source/image binding receipt, SHA-256 `094a39b86087682bc3d2094793949395ecb5a650efd73387bbbbad46ea3e2624`; indexed in the supplement |
| `cryptography-static-native.json` | Measured embedded-SSL/module record, SHA-256 `bd21b52cec5964145c28d50f4b1bb9ef1d9bbc7e2217ff6f4c046acb14d3dc36`; module bytes separately matched against the current locked wheel |
| `distro-notices/` | 15 actual package copyright records plus 26 common-license files captured from the built runtime; every copied text is checked against the source inventory SHA-256 |
| `openssl-4.0.3-upstream/` | Three exact tagged primary text files and source URL/digest index; LICENSE.txt SHA-256 `7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a` from [the official upstream tag](https://github.com/openssl/openssl/blob/openssl-4.0.3/LICENSE.txt) |
| `additional-materials.json` | Separate supplement index for runtime receipt, static native record and upstream texts; SHA-256 `f11d5168af17b216a5e46af86395c22236edf6e7216c70420b87dc8abd83c55c` |

Common-license file availability does not mean every listed licence applies to
a shipped component. Review each actual Debian package copyright record and
its relevant text/source obligations. Do not infer an AGPL or GPL dependency
solely because a corresponding common-license file is present.
The exact upstream root listing contains no NOTICE-named file; that narrow
observation does not establish absence of all source/build notice obligations.

The raw archive is a local review artifact under ignored `.tmp-test/`; it must
be deliberately included in the final delivery evidence. A tracked inventory
or this draft link does not deliver the raw notices to a customer.

## Operating-system package notice snapshot

A separate bounded, read-only and network-disabled extraction of the same
exact final image supplies its full **installed dpkg package** notice inventory:
110 package/version records, 110 readable package copyright texts,
26 common-license texts and raw dpkg status (137 preserved raw materials).
The dpkg-query/status crosscheck matched; all 137 copied file hashes were
independently rechecked. Missing/unreadable package copyright records: zero.

The local draft archive is
`.tmp-test/production-followup-2026-10-06/bridge-full-os-notice-review/`.
Its [tracked inventory](./evidence/bridge-full-os-notice-inventory-2026-10-06.json)
is an exact copy of `inventory.json`, SHA-256
`c21b76af4c36696555b407c12a8996ea1940f7fe6ced41e6db7ac50504fc0da9`;
`image-inspection.json` SHA-256 is
`765b17fa22b2c872c0f74e8215c7e61ff9629179689dc5f018a347becb5b84c2`.
The recorded command does not run the application entrypoint, build, install
or update the image. The temporary collection container was removed.

This closes the missing local **dpkg notice collection** input for that image,
not COM-002. It does not establish applicable licence terms, source obligations,
security clearance, complete coverage of non-dpkg binaries/static dependencies,
other images/platforms or customer acceptance. Preserve and review the actual
texts before final delivery; common-license presence alone is not applicability.

## Regenerate and validate before release review

Use verified wheels and an actual runtime extraction for the selected build.
The archive command executes no wheel code and never overwrites existing
evidence. The optional runtime input validates/copies recorded copyright bytes;
it does not independently run or authenticate the image.

```sh
python scripts/archive-pypi-license-materials.py \
  --wheels .tmp-test/production-followup-2026-10-06/bridge-system-libpq-security/runtime-wheels-crypto-50.0.2 \
  --native-inventory .tmp-test/production-followup-2026-10-06/bridge-system-libpq-security/final-crypto-50.0.2/native-runtime-inventory.json \
  --output .release-evidence/selected-bridge-notice-review

node scripts/generate-sbom.mjs --output .release-evidence/selected-source-sbom.cdx.json
node scripts/generate-license-report.mjs \
  --sbom .release-evidence/selected-source-sbom.cdx.json \
  --output .release-evidence/selected-source-license-report.json \
  --markdown .release-evidence/selected-source-license-report.md --strict

node scripts/verify-commercial-compliance.mjs
```

The archive command produces the wheel/system-libpq index and texts. It does
not regenerate the supplement automatically: collect the selected image's
static module and image/source receipt, match module bytes to the locked wheel,
and preserve each upstream text and recorded digest before signing the final
delivery inventory. The current `additional-materials.json` supplies the exact
existing material paths, URLs and hashes for reviewer comparison.

The current local SBOM snapshot is
`.tmp-test/production-followup-2026-10-06/crypto-50.0.2-commercial-sbom.cdx.json`
(SHA-256 `45b3184458ebe7a84e6de438f12f8706fd42cc73b393c568b13366f09ec7a354`).
Its licence report is `crypto-50.0.2-commercial-license-report.json` in the same
directory (SHA-256 `eeb1fa76dc3571e486ec0e2417c5e99c90ffad5673ab83dc2ead42d23d1b97c1`).
Neither is a signed candidate or an approved delivery inventory.

## Remaining review inputs

Engineering must bind the selected wheel, native runtime and notice archive to
the final signed candidate/image identities; include these source/runtime/dpkg
snapshots and complete the selected non-dpkg/static and other upstream-container
inventories; and preserve applicable notices, source
availability and attribution in the actual distributed or hosted materials.
Legal must review the exact delivery model and these obligations, chain of
title and the preserved AIG/DRL notices. The two current register entries keep
their owner, reviewer, approval date and expiry **unknown**. Ordinary compliance
may resolve review without granting a licensing exception.

The removed psycopg-binary 3.2.10 wheel has a separate
[historical 14-library inventory](./evidence/native-library-inventory-2026-10-06.json)
and local archive
`.tmp-test/production-followup-2026-10-06/historical-31-wheel-notice-review/`.
Those materials preserve earlier byte identities and upstream references.
They do not establish the current dependency set, an approved waiver, security
clearance or satisfaction of any past distribution obligation.

The earlier `current-30-wheel-and-distro-notice-review/` archive and libpq-only
receipt `c43a72fe…` are also superseded historical preparation snapshots from
before the cryptography 50.0.2 patch; use the current paths and hashes above.
