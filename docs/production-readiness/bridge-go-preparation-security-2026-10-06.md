# Bridge GO preparation — actual image verification, 2026-10-06

The new bridge image removes unnecessary runtime components and upgrades the interpreter to its current security release. Actual-image verification passes **98 tests, zero failures and zero skips**, certificate-verified PostgreSQL TLS, and four readiness-probe cases. The same full-image scanner/database comparison reduces **241 findings to 181**, including **52 HIGH to 40**. **All 181 remaining findings stay OPEN; this preparation does not approve security/legal acceptance or change GA from NO_GO.**

This report supersedes the runtime/image bindings for new GO preparation. The [previous 248 → 241 report](bridge-image-security-2026-10-06.md) and its complete initial findings remain unchanged historical evidence. The [new complete machine evidence](evidence/bridge-go-preparation-security-2026-10-06.json) includes every 241 baseline and 181 final advisory/package row, vendor status, fixed version, references and all 60 removed rows. No suppression, mixed-distribution repository or metadata hiding was used.

## Minimal changes and supported base

- The bridge's Docker and Compose readiness checks now use Python's standard HTTP library with a three-second timeout, bypassing ambient proxies and retaining `/api/v1/readyz`.
- The Dockerfile omits curl. Its unused libcurl and other transitive packages are therefore absent from the final image.
- Normal apt purge removes the optional `mount` package. Actual-image inspection confirms `curl`, `mount` and `umount` commands are absent. No Essential or Protected package removal was forced.
- The base remains Debian Trixie, with the official pinned **Python 3.12.15** image. Runtime lock files and the bridge application source are unchanged. The existing OpenSSL/PCRE2 floors and removal of pip/ensurepip remain in place.

Official base: `python:3.12.15-slim-trixie@sha256:ddb0207ae1f0356c2b724d740769b0c5f5f51cc54a0525178f721825f78fe74c`. Its amd64 manifest is `sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe`. The pinned [Docker Official Images source](https://github.com/docker-library/python/blob/2a3b794c223ab067d122719541cdd54a068732a5/3.12/slim-trixie/Dockerfile) confirms Trixie and Python 3.12.15.

Python 3.12.15 is an official security release covering **CVE-2026-19445, CVE-2026-19553, CVE-2026-82049, CVE-2026-15310, CVE-2026-19672, CVE-2026-15806, CVE-2026-17084 and CVE-2026-87910**, with bundled Expat updated to **2.8.5**. These interpreter fixes are recorded separately from distribution-package scanning. [Official release and individual security references](https://www.python.org/downloads/release/python-31215/).

Actual runtime evidence observes Python **3.12.15**, Expat **2.8.5**, and these bytes:

| Actual image component | SHA256 |
| --- | --- |
| `/usr/local/bin/python` | `0e6475dfda68a9b2d93501449fc47593ca169010e8f4881577b97463fd0c1263` |
| Loaded `/usr/local/lib/libpython3.12.so.1.0` | `eb1599eecbe4002798fdcec98d0f4d85dab01afaaa8db89b39c5d30abdb9f5aa` |
| `pyexpat.cpython-312-x86_64-linux-gnu.so` | `11eb83c00b747bb59c11ae229d437eee4a4757892cf41b2cee9cace7f87443f4` |

The receipt also records loaded-library evidence, `pyexpat` native dependencies and hashes for `ssl`, `_ssl`, `tarfile`, `zipfile`, `urllib.parse` and `stringprep`. An ordinary Python-distribution inventory does not independently scan custom-built CPython, so zero Python-package findings alone would not establish interpreter security. [Trivy Python coverage](https://trivy.dev/docs/latest/guide/coverage/language/python/).

## Exact release component and validation

| Binding | Value |
| --- | --- |
| Image index | `sha256:d50d54dec310055d30544954927e1194c4375a1a40a03633f0c1aa6a0f629794` |
| Linux/amd64 manifest | `sha256:1b835b8229c8d36d9daaa976624a9ae4ba0e20e89c08f21701e45c162112f61a` |
| Config digest reported by Trivy | `sha256:286ccc483a4793cda11e97ef588c6d5a5ae7a3f734d9e8c2a3a1bb1e5b551681` |
| Dockerfile SHA256 | `9dabfe33f3144b2f52cea16cb0ef5db2f01b8e261a6a46ce009f80dae8f9ad61` |
| Compose SHA256 | `3be3da5b4e0d5a06a32aa7249ae08af804f25c9d30fa45f718214aabc87612b1` |
| Unchanged runtime lock SHA256 | `af4cf84b33c07df728ddb2e8b9a0f10c1d4f8f309295cc18bf808b8377a5c598` |
| Unchanged CI lock SHA256 | `b5cbbd7c0e9c0d0b9ea1c7f1653250fcc091738a45e411eb892c52d17dd8ffbe` |

The receipt verifies the archive index → manifest → config hashes and all ten layer DiffIDs against Docker inspection and Trivy. Every current application source SHA matches the actual image. The **30 installed Python distributions exactly match the runtime lock**. Tests run against image `/app`, with no application source mount; they include live multi-session PostgreSQL task/quota/lease and JWT replay races. Temporary CI bootstrap tooling remains outside the runtime image.

The separate connection probe uses the default nonroot user and `sslmode=verify-full` against a disposable PostgreSQL server and a synthetic certificate. It verifies the `bridge-postgres` hostname and observes **TLS 1.3 / TLS_AES_256_GCM_SHA384**, pure Python psycopg **3.2.10** and system libpq **170011**. System OpenSSL remains **3.5.7**, cryptography **50.0.2**, and embedded OpenSSL **4.0.3**. The exact Docker readiness command matches Compose and passes four cases: HTTP 200 succeeds; HTTP 503, timeout and refused connection fail. A deliberately invalid ambient proxy does not intercept the local probe.

Owned test containers, PostgreSQL container, named data volume and private test network were removed after identity/label checks. The actual image and local archive are retained for optional portable delivery. They are verification inputs, with no automatic publisher or acceptance approval.

## Full scan and remaining constraints

The scanner is official checksum-verified **Trivy 0.75.0**, using the same official DB schema 2 snapshot updated **2026-10-05 19:07:00.467981014 UTC** as the historical baseline. The new offline scan completes **2026-10-06 07:23:47 UTC**, with networking and DB updates disabled. All severities and unfixed advisories are included, with an empty ignore file and policy. Exact arguments, dates, database identity and original report hashes are in the machine evidence. [Scanner release](https://github.com/aquasecurity/trivy/releases/tag/v0.75.0), [DB documentation](https://trivy.dev/docs/latest/configuration/db/).

| Measure | Previous repaired image | GO preparation image |
| --- | ---: | ---: |
| Advisory/package rows | 241 | 181 |
| Unique advisory IDs | 111 | 82 |
| HIGH | 52 | 40 |
| MEDIUM | 82 | 58 |
| LOW | 105 | 81 |
| UNKNOWN | 2 | 2 |
| CRITICAL | 0 | 0 |
| Vendor fixed version available | 0 | 0 |
| Installed OS packages | 110 | 96 |
| Locked runtime Python distributions | 30 | 30 |

All four curl HIGH IDs are absent from the new image: **CVE-2026-12064, CVE-2026-8286, CVE-2026-8458 and CVE-2026-8927**. Removing the `mount` binary package removes four additional HIGH rows for **CVE-2026-76642, CVE-2026-78408, CVE-2026-78409 and CVE-2026-78410**. Those four util-linux source CVEs remain detected against other installed packages; they are not claimed globally fixed. Unneeded curl dependencies also account for the remaining removed MEDIUM/LOW rows. Every removed row is retained in the evidence.

The **40 remaining HIGH rows represent eight CVEs**, all OPEN:

- util-linux: [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642), [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408), [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409), [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410).
- ACL: [CVE-2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369).
- ncurses: [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720).
- systemd: [CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742).
- Perl: [CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538).

The final vendor statuses are **179 `affected` and two `fix_deferred`**. Every HIGH/MEDIUM/LOW/UNKNOWN row remains OPEN without a waiver. Vendor fix availability and source/version conflicts require security review, not silent suppression.

The prior exact-image inspection records all 110 packages, 780 actual ELF objects and ordinary apt removal simulations. `bsdutils`, `util-linux`, `ncurses-base`, `ncurses-bin` and `perl-base` are **Essential**; `login` is **Protected**. Ordinary apt rejects removals of their required libraries. Actual Python `_uuid` needs `libuuid.so.1`, and `_curses` needs `libncursesw.so.6`/`libtinfo.so.6`; removing only the 17 libpq dependencies would break standard-library functionality. No forced package removal or ad hoc copying of selected files to hide package inventory was attempted. The actual new image and tests validate the chosen optional removal.

That inspection does not find `Archive::Tar` in the installed Perl module search paths or `Archive/Tar.pm` in examined trees, nor systemd-homed/homectl at the inspected paths. These observations narrow current code presence; they do not waive the Perl/systemd vendor package rows or prove every deployment unreachable.

A Bookworm migration was evaluated and rejected as a verified clearance route: the current Debian tracker still labels all 12 baseline HIGH IDs vulnerable there. Upstream ranges conflict for [CVE-2026-78408](https://github.com/util-linux/util-linux/security/advisories/GHSA-55fx-f4gg-cfhj) and [CVE-2026-78409](https://github.com/util-linux/util-linux/security/advisories/GHSA-8f2p-47x3-43mv); those conflicts are recorded, with no automatic waiver. No unstable or mixed-suite repository is configured.

## Local portable artifacts and notice evidence

| Artifact under `.tmp-test/go-preparation-2026-10-06/bridge/` | Bytes | SHA256 |
| --- | ---: | --- |
| `image.tar`, actual Docker-save/OCI image | 65,480,192 | `980b4d8fbe80b09bc4d27a357a7cc10e86810e1e9d4bd774ba386ae3059bc465` |
| `native-os-notices.tar.gz`, raw notice materials and inventory indexes | 659,777 | `863ea484f0755cff8e6ea47ae05d4d9b5fa452dfc247b6a2cf648191a8eee836` |

The new exact image has **17 native library paths**, **41 native notice materials**, **96 OS packages**, **96 package copyright texts**, **26 common licenses**, and a copied package-status file. All **164 copied notice materials** match their hashes; missing/unreadable and unowned native paths are zero. Native owners/versions match the OS inventory. The archive contains those materials plus their collection/index/proof files. It carries public notice evidence, not customer credentials.

Inventory SHA256 values: native `3c463d75a1acc45fe01deb97e21caa659d2b9d12fced0d7ffe431a90b5bb098e`; OS `3017759c0db1f439d42bb00b9ab7586cdf06d15553eab5e952a747546a4f9569`; embedded cryptography `c6937512470ea456a3230cd54d9b36b1c829a1e82fcc8c0f7140000c4bfcb1e9`. The notice aggregate at `notices/summary.json` has SHA256 `400bcfb7fb6d9bed2ffbb7971bb82c3862649a07271bc9acb0881b52ea611560`. All remain draft legal/security review inputs.

The complete aggregate is `runtime-security-receipt.json` in the same scratch directory and is byte-identical to the tracked machine evidence, SHA256 `c903e4645b711b35ed2ba0aafc13078dadfc808bae0ff61e92b1d04423e66fa1`. Source/image preparations and local verification are complete; remaining vendor findings and field/security/legal/publisher decisions remain OPEN. No production acceptance is inferred from the passing tests or reduced totals.
