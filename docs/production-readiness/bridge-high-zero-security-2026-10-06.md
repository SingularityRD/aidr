# Bridge runtime security repair — 6 October 2026

The exact new bridge image has **0 HIGH, 0 CRITICAL and 0 findings at every
scanned severity**. The same official Trivy database reported 181 advisory/package
rows, including 40 HIGH across eight CVE IDs, in the preceding Debian image.
The actual new image passed **98 tests, 0 failures, 0 skips**, two real PostgreSQL
race tests, a nonroot PostgreSQL TLS verification probe and four readiness-command
checks. This is local technical evidence; Security, Legal and publisher acceptance
remain separate and OPEN. No exception or waiver was granted.

The [complete machine receipt](./evidence/bridge-high-zero-security-2026-10-06.json)
retains the full preceding 181-row finding list and the final measured result.
The [unfiltered final scanner report](./evidence/bridge-high-zero-full-image-scan-2026-10-06.json)
lists all **47 APK packages and 30 Python packages**. Earlier [GO preparation](./bridge-go-preparation-security-2026-10-06.md)
and [initial full-image findings](./bridge-image-security-2026-10-06.md) remain
historical proof and have not been rewritten as successful acceptance.

## Minimal runtime change

Only the bridge Dockerfile and its selected-wheel licence evidence change in this
lane. The 30-package runtime lock, CI lock and application source remain unchanged.
The supported official Python 3.12.15 Alpine 3.24 base replaces the Debian base.
No unstable repository, forced protected-package purge, severity override,
metadata deletion or advisory ignore is used. The original runtime removes the
unused pip/ensurepip code after installation; intact APK package metadata is
retained and cross-checked against the scan.

The base is pinned to
`python:3.12.15-alpine3.24@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4`.
Its [official Dockerfile](https://github.com/docker-library/python/blob/2a3b794c223ab067d122719541cdd54a068732a5/3.12/alpine3.24/Dockerfile)
is recorded with primary source hashes. Alpine 3.24 main support ends on
1 June 2028; community has a shorter lifecycle. The required installed APKs are
recorded separately from that support statement. [Alpine release policy](https://alpinelinux.org/releases/).

Security minimums select actual libpq **18.6-r0**, OpenSSL **3.5.9-r0**, musl
**1.2.6-r2**, BusyBox **1.37.0-r31**, SQLite **3.53.4-r0**, libuuid **2.42.3-r1**
and ncurses **6.6_p20260516-r0** from the stable repository. Minimums permit later
supported fixes; a future rebuild must produce fresh image/version/scan evidence.
The measured archive, rather than a future APK resolution, binds this report.

The first Alpine candidate revealed a real startup failure: Python's standard
library finder could not locate the installed versioned libpq library. Standard
`binutils` and `libpq-dev` provide its linker and library-name lookup requirements.
A build assertion now imports pure psycopg and verifies the actual libpq version
before removing the installer. No driver monkeypatch or bundled binary PostgreSQL
driver was added. [CPython library finder](https://github.com/python/cpython/blob/v3.12.15/Lib/ctypes/util.py),
[psycopg library loading](https://github.com/psycopg/psycopg/blob/3.2.10/psycopg/psycopg/pq/misc.py).

## Resolution of the eight preceding HIGH IDs

| Advisory | Previous HIGH rows | Actual final disposition |
|---|---:|---|
| CVE-2026-76642 | 8 | Required util-linux-derived libuuid is 2.42.3-r1; upstream/vendor fix record verified. Other former Debian util-linux binaries/libraries are absent. |
| CVE-2026-78408 | 8 | libuuid 2.42.3-r1 includes the explicit Alpine r1 patch. |
| CVE-2026-78409 | 8 | libuuid is newer than the vendor 2.42.3-r0 fix floor. |
| CVE-2026-78410 | 8 | libuuid is newer than the vendor 2.42.3-r0 fix floor. |
| CVE-2025-69720 | 4 | Actual ncurses source version includes the upstream bounded-copy/termination fix; `infocmp` executable is absent. |
| CVE-2026-16742 | 2 | The systemd/udev packages and their native libraries are absent in the measured Alpine image. |
| CVE-2026-54369 | 1 | The ACL package/native library is absent in the measured image. |
| CVE-2026-9538 | 1 | Perl is absent in the measured image. |

The [primary vendor proof](./evidence/bridge-high-zero-vendor-proof-2026-10-06.json)
preserves all four util-linux advisories, package fix records and source checks.
The exact **installed** aports commit for libuuid has the same APKBUILD bytes as
the checked fix evidence. The exact installed ncurses APKBUILD names the same
SHA-512-verified source archive; its `infocmp.c` contains length bounds and
termination at lines 909–912. [util-linux advisories](https://github.com/util-linux/util-linux/security/advisories),
[installed util-linux source](https://github.com/alpinelinux/aports/blob/d98c55af59055e6ca60fbe36e171546918709965/main/util-linux/APKBUILD),
[ncurses fix history](https://invisible-island.net/ncurses/NEWS.html#index-t20251213).
BusyBox's own `mount`, `umount` and `nsenter` applets remain; they are different
code, not a false claim that all such command names were removed.

## Coverage beyond package detection

The captured Alpine security database lacks the thirteen OpenSSL 3.5.9 advisory
entries, including HIGH CVE-2026-84782, and SQLite CVE-2026-11822/11824. It also
has no ncurses CVE-2025-69720 fix row. These gaps are explicitly retained rather
than used as clearance. Actual system OpenSSL is **3.5.9**, actual SQLite is
**3.53.4**, and exact ncurses packaged source is checked independently.
[OpenSSL 29 September advisories](https://openssl-library.org/news/secadv/20260929.txt),
[SQLite CVE records](https://www.sqlite.org/cves.html).

The loaded interpreter is **Python 3.12.15** with **Expat 2.8.5**. The official
release resolves CVE-2026-19445, 19553, 82049, 15310, 19672, 15806, 17084 and
87910. Actual interpreter, loaded libpython, pyexpat and related module hashes
are recorded, preserving the previous Python repair. Cryptography 50.0.2
imports embedded **OpenSSL 4.0.3**; its musllinux module and any bundled native
payload have separate physical-byte records. [Python 3.12.15 release](https://www.python.org/downloads/release/python-31215/).
The package scan is not independent complete CVE coverage for custom compiled
code, customer configuration or every possible runtime path.

## Exact image and verification

| Binding | Value |
|---|---|
| Final image index | `sha256:dd8993b9abaed977cc6d6a123a39388f188ba86d83552b140935773005b3d195` |
| Linux/amd64 manifest | `sha256:9dc3101ee675d0f404fdc4fb4a362ae1186040013cadb27f5578113a38bf3a47` |
| Image config reported by Trivy | `sha256:6e7b84bf460c0a803b726cd9e35f0f18aef963d1d5c31eccc9c28e2a7534a5e2` |
| Dockerfile SHA-256 | `a18e7731d502a51744c91630e26f706d70d897c237226ef8e6000eb8a5973d7e` |
| Runtime lock SHA-256 | `af4cf84b33c07df728ddb2e8b9a0f10c1d4f8f309295cc18bf808b8377a5c598` |
| Compose SHA-256 | `3be3da5b4e0d5a06a32aa7249ae08af804f25c9d30fa45f718214aabc87612b1` |
| Image archive | `.tmp-test/high-zero-2026-10-06/bridge/image.tar`, 48,484,352 bytes |
| Archive SHA-256 | `b59a64cac6db18c36852e6edea41a1f85e81c6764be136930e0fa5ec6ef3640f` |

The [independent archive audit](./evidence/bridge-high-zero-archive-audit-2026-10-06.json)
verified all 16 archive blobs, the image index/manifest/config chain and all ten
decompressed layer identifiers against Docker and Trivy. All 18 image application
source files and the runtime lock match current source bytes. All 30 installed
Python distributions and all 47 intact APK metadata entries match scanner scope.

The exact final repository build command is recorded in the receipt. Tests run
the image's actual `/app` code with only tests, migrations and Compose mounted.
Hash-locked CI tooling runs in an ephemeral test environment and is not runtime
image content. Both real PostgreSQL cross-instance race tests ran without skips.
The default UID/GID 1000 image connects to an owned PostgreSQL 17 fixture with
`sslmode=verify-full`, TLS 1.3 and `TLS_AES_256_GCM_SHA384`, using a read-only
filesystem and dropped capabilities. No host port or live deployment is used.

The four readiness cases exercise the exact Dockerfile/image/Compose Python
command against controlled healthy, HTTP 503, timeout and refused peers. They
verify `/api/v1/readyz`, bounded timeout and ambient-proxy bypass. They do not
substitute for a live AIG worker/customer installation test. Owned PostgreSQL,
network and volume and the synthetic TLS private key were removed afterward.
The new image/archive and preceding evidence are retained.

## Scanner and redistribution inputs

Official Trivy **0.75.0** is SHA-256 checked against its published release checksum
manifest. This proof claims checksum verification, not independent cosign
verification. The unchanged official DB version 2 was updated at
**2026-10-05 19:07:00 UTC**; its next update is 6 October at 19:07 UTC. Final scan
ran at **2026-10-06 10:09:53 UTC**, offline without a DB change. DB SHA-256 is
`3360d4fd28e3f89b0e484b19fcea2230d4ce9003596aead075831a20683c074d`.
OS and language scans include UNKNOWN/LOW/MEDIUM/HIGH/CRITICAL and unfixed entries,
using empty config, ignorefile and ignore policy. [Official Trivy release](https://github.com/aquasecurity/trivy/releases/tag/v0.75.0).

The [actual APK/native inventory](./evidence/bridge-high-zero-apk-native-inventory-2026-10-06.json)
records 47 package versions/origins/licence declarations, 46 observed native paths,
raw package metadata and 37 physical Python/CPython notice texts. All 47 APKs lack
installed physical licence/copyright texts; APK declarations are not full notice
fulfilment. Exact upstream source, licence, Alpine build/config/patch records
are prepared separately for review, including BusyBox, binutils and libpq. The
[source-material index](./evidence/bridge-high-zero-legal-source-inventory-2026-10-06.json)
now records **252 SHA-512-verified installed-origin inputs**, 33 source archives
and all 15 declared lifecycle/trigger controls for **46 real APK packages across
33 exact recipes**. The [package boundaries](./evidence/bridge-high-zero-package-boundaries-2026-10-06.json)
explicitly exclude `.python-rundeps` as empty virtual metadata. The automatically
retrievable source/notice collection gaps have been closed. All complete source
archives are preserved alongside **164 extracted upstream licence/header materials**:
152 full texts and 12 explicitly labelled header prefixes.
Ten further candidate utmps/skalibs inputs bring the pack total to **262 verified
inputs and 35 source archives**; their exact static-binary linkage remains unproved.
The final portable source/notice pack is
`.tmp-test/high-zero-2026-10-06/bridge/legal-complete/full-declared-source-materials.tar.gz`,
317,367,132 bytes, SHA-256
`7dbadf8f83512ff0c6e653aec3c90e5a1e20cc4e031ebbe9ad6a06eb1a0066c9`.
Its manifest binds 641 material files. The initial pack remains immutable:
`.tmp-test/high-zero-2026-10-06/bridge/legal/legal-notice-source-materials.tar.gz`,
82,252,253 bytes, SHA-256
`d0c1398425fef4fb6d05792eec800ebeb0c07962c1c689e1f185b7380510cd0f`.

The two remaining engineering provenance boundaries are precise: the actual
stable BusyBox APK/control/binary matches the image, but the surviving edge
build log cannot be bound to it, so its exact compiled static utmps/skalibs
source mapping is unproved; the three wheel-packaged libgcc source-to-byte and
applicable-term mappings are also unproved. These are distinct from completed
declared-material collection and from human Legal/distribution acceptance.

The canonical [selected Python wheel metadata](../../services/aig-bridge/pypi-runtime-licenses.json)
now describes the actual Alpine-selected wheels. Thirty wheel hashes remain
within the unchanged runtime lock; eight native wheel filenames change, while
all 36 dist-info licence-text hashes equal the historical selection. Three
musllinux wheels additionally bundle `libgcc_s` payloads. Their exact bytes and
unresolved independent source/terms are recorded; wheel licence equality does
not establish GCC runtime obligations. The [bounded publisher provenance trace](./evidence/bridge-high-zero-libgcc-provenance-2026-10-06.json)
records that cryptography's exact wheel SBOM declares libgcc **14.2.0-r6**,
without licence/source/hash fields or an independently verified builder mapping.
The other two exact-wheel provenance endpoints returned 404. APK GCC 15.2.0
source is bundled for the APK libraries and is not assigned to these wheel copies.
The [notice review pack](./bridge-notice-review-pack-2026-10-06.md)
links the fresh review inputs and preserves the earlier Debian records.
The prepared wheel licence ZIP is
`.tmp-test/high-zero-2026-10-06/bridge/wheel-licenses/wheel-license-materials.zip`,
87,640 bytes, SHA-256
`b8e08d598f4f557a2a12f79c5c3fb34b6a50bac355ad954bab7828c96e16ad9a`.
These materials do not fabricate a publisher's corresponding-source offer,
Legal approval, customer acceptance or product-wide production readiness.
