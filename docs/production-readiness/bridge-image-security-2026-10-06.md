# Bridge image security verification — 2026-10-06

The repaired bridge image passes **98 tests, with zero failures and zero skips**, and a real PostgreSQL connection with certificate and hostname verification. The full image rescan removes all **7 findings with an available fixed version** from the initial report. **241 advisory/package rows remain OPEN, including 52 HIGH rows. GA remains NO_GO; T29 field/security acceptance remains OPEN.** This verification does not grant a security waiver, customer acceptance or release approval.

The [machine evidence](evidence/bridge-image-security-2026-10-06.json) contains **every initial and final finding**, including advisory/vendor IDs, package, installed version, severity, vendor status, available fixed version and source references. Its `initial.findings` has 248 rows; `repaired.findings` has 241 rows; `removed_findings` records the seven repairs. There are no suppressions or waived rows. Evidence SHA256: `df8c936046f604690d015e2903abf0d53c4488efc2fcc15bb4a17fa042a1f550`.

## Exact image and source bindings

| Binding | Value |
| --- | --- |
| Initial image index | `sha256:f3e9e8b6571b532e221ce27461b6fb09b735923eba7a771fcac70b52cb7d8a35` |
| Repaired image index | `sha256:1840809665e666eec7c89cc7fb451fa7b65210d37dcf7ee0a41f7eb82390386a` |
| Repaired Linux/amd64 manifest | `sha256:253a25f2cb549309d2e3135576cfbebd9957142be7a77528cd3eaa9d30d9c90a` |
| Repaired image config | `sha256:2bfdfefccf8da11133b9315cc4992ed7236993e4d6b610e22eacc210b4af2ae6` |
| Repaired image archive SHA256 | `7beb83252345cf9a87cb5bcf7e2a9085ac4f954e912eae4fc19e13b95b39ff1b` |
| Dockerfile SHA256 | `778d724672f716732de04af29588b6c5ea1ebc1c88c62cc355d0bc9bf4887d93` |
| Runtime lock SHA256, unchanged | `af4cf84b33c07df728ddb2e8b9a0f10c1d4f8f309295cc18bf808b8377a5c598` |
| CI lock SHA256, unchanged | `b5cbbd7c0e9c0d0b9ea1c7f1653250fcc091738a45e411eb892c52d17dd8ffbe` |

Docker exposes the OCI index digest; Trivy's archive report exposes the image config digest. The receipt verifies the archived index → amd64 manifest → config hashes and checks all ten layer DiffIDs against Docker inspection and the report. Those different identifiers refer to the same verified image. Every current bridge application source SHA matches the application's actual bytes in that image.

The complete aggregate is `.tmp-test/production-followup-2026-10-06/bridge-full-image-trivy-20261006/repaired/runtime-security-receipt.json`. The initial raw report remains unchanged at the sibling `trivy-report.json`; the repaired raw report is `repaired/trivy-report.json`. Their SHA256 values are `1348d33657210d96a5f4a5f461ae2a386d060cf902058875aadb1d134901f784` and `677f79c1ec5ecef26d3266ae7faff2f2ed1d8869ae59ff995bdd2478dbc3f167`, respectively. Complete redacted finding lists remain in the tracked machine evidence even when local scratch artifacts are unavailable.

## Scanner and comparison

The scanner is [official Trivy v0.75.0](https://github.com/aquasecurity/trivy/releases/tag/v0.75.0). The Linux archive SHA256 `c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f` matched the immutable official release asset and published checksum manifest. This is checksum verification; no cosign signature verification is claimed.

Both scans use vulnerability DB schema **2**, updated **2026-10-05 19:07:00.467981014 UTC**, downloaded **23:43:42.066910924 UTC** from the official Trivy DB repositories. The repaired scan completed **23:51:59 UTC** using the identical cached DB, with networking disabled and DB updates disabled. The document date is 2026-10-06 in Europe/Istanbul. [Official DB documentation](https://trivy.dev/docs/latest/configuration/db/).

The scans include OS and language packages, every severity, unfixed advisories and all installed package inventory. The ignore file and policy are empty. Exact scanner arguments and process timestamps are in the machine evidence. Containers had a read-only root filesystem, no Docker socket, all capabilities dropped and no host secrets mounted.

| Finding measure | Initial | Repaired |
| --- | ---: | ---: |
| Advisory/package rows | 248 | 241 |
| Unique advisory IDs | 118 | 111 |
| CRITICAL | 0 | 0 |
| HIGH | 53 | 52 |
| MEDIUM | 87 | 82 |
| LOW | 106 | 105 |
| UNKNOWN | 2 | 2 |
| Findings with a fixed version available | 7 | 0 |
| OS packages inventoried | 110 | 110 |
| Python distributions inventoried | 31 | 30 |
| Python vulnerability rows | 6 | 0 |

These are package/advisory rows; one source-package CVE can appear against several installed binaries. The final vendor statuses are 239 `affected` and two `fix_deferred`. The initial `fixed` status means a vendor fix was available, while the installed version was still affected. It does not mean the initial image was fixed.

## Repairs and actual runtime verification

The Dockerfile installs `libpcre2-8-0` and fails the build unless its Debian version is at least **10.46-1~deb13u3**. The new image contains that version. It removes the HIGH **CVE-2026-103111** finding; Debian identifies the preceding u2 build as affected and u3 as fixed. [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2026-103111), [DSA-6530](https://security-tracker.debian.org/tracker/DSA-6530-1).

After the hash-locked runtime installation and dependency check, the image actually uninstalls unused **pip 25.0.1** and removes `ensurepip`, including its bundled installer wheel. Actual-image inspection confirms the pip module, pip distribution metadata and ensurepip module are all absent. The removed pip advisories are **CVE-2025-8869**, **CVE-2026-13346**, **CVE-2026-3219**, **CVE-2026-6357**, **CVE-2026-8643** and **CVE-2026-1703**; their individual installed/fixed versions remain in the evidence. Runtime package installation is a build step; there is no runtime installer requirement. For example, CVE-2026-13346 concerns installing from a malicious package index. [PyPA advisory](https://github.com/pypa/advisory-database/blob/main/vulns/pip/PYSEC-2026-3721.yaml).

The installed **30 runtime distributions exactly match the unchanged runtime lock**. CI tooling used an isolated temporary environment and an official SHA-verified pip 26.2.0 bootstrap wheel, normalized by PyPI as 26.2. That tooling is excluded from the runtime image and inventory. Its wheel SHA256 is `931c303696af6fa3417112103b1cad26890e5a07eccb5b99783700e33f2b8aad`.

The **98 tests** execute against `/app` from the new image; application source is not mounted from the checkout. Tests include real multi-session PostgreSQL task/quota/lease and JWT replay races on a disposable database. The separate TLS probe uses the image's default nonroot user, verifies a synthetic local certificate and the `bridge-postgres` hostname, and observes **TLS 1.3 / TLS_AES_256_GCM_SHA384** with pure Python psycopg and system libpq **170011**. The application runtime remains Python **3.12.14**, system OpenSSL **3.5.7**, cryptography **50.0.2** and embedded OpenSSL **4.0.3**. Owned test containers and the owned PostgreSQL network were removed; the historical and repaired images were preserved.

New-image notice extraction inventories **17 actual native library paths**, **41 native notice materials**, **110 OS packages**, **110 package copyright texts** and **26 common license texts**. Native and OS package owners/versions agree, all 137 saved full-OS files and 41 native notice materials match their hashes, and missing/unreadable materials are zero. These are draft review materials, with legal acceptance still OPEN.

## Remaining HIGH findings: explicit OPEN disposition

The 52 HIGH rows represent **12 distinct CVEs**. Every row remains OPEN; no current vendor fixed version is provided in the scanned DB. The prerequisites below are source context, not a finding that exploitation is impossible in a deployment.

| Source package and IDs | Vendor context; remaining disposition |
| --- | --- |
| curl — [CVE-2026-12064](https://curl.se/docs/CVE-2026-12064.html), [CVE-2026-8286](https://curl.se/docs/CVE-2026-8286.html), [CVE-2026-8458](https://curl.se/docs/CVE-2026-8458.html), [CVE-2026-8927](https://curl.se/docs/CVE-2026-8927.html) | Respectively involve CLI schemeless SFTP/SCP URLs, STARTTLS connection reuse, HTTP Negotiate connection reuse across service names, and libcurl Digest proxy reuse. The image contains curl/libcurl **8.14.1-2+deb13u5**. A [proposed Debian u6 update](https://lists.debian.org/debian-release/2026/09/msg00073.html) is not proof of an available or installed fix. All four remain OPEN. |
| util-linux — [CVE-2026-76642](https://github.com/util-linux/util-linux/security/advisories/GHSA-m25x-3hj9-m26f), [CVE-2026-78408](https://github.com/util-linux/util-linux/security/advisories/GHSA-55fx-f4gg-cfhj), [CVE-2026-78409](https://github.com/util-linux/util-linux/security/advisories/GHSA-8f2p-47x3-43mv), [CVE-2026-78410](https://github.com/util-linux/util-linux/security/advisories/GHSA-rh77-686x-2f2m) | Involve privileged mount hooks after helper failure, privileged `nsenter --join-cgroup`, restricted SUID mount with `X-mount.subdir`, and restricted bind-source resolution with ownership/mode hooks. Four CVEs generate **36 rows across nine binaries**. Installed Debian util-linux **2.41.5-0+deb13u1** remains affected per the scanned vendor records; all four remain OPEN. Exact epoch/repack versions for each binary are in the machine evidence. |
| ACL — [CVE-2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369) | Requires a privileged pathname-based ACL caller with attacker-controlled path components. New `acl_*_at()` APIs require caller adoption; upgrading the library alone does not change legacy API semantics. Installed libacl1 **2.3.2-2+b1** remains OPEN. [Maintainer explanation](https://www.openwall.com/lists/oss-security/2026/06/29/1). |
| ncurses — [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | Concerns `infocmp` CLI `analyze_string`; upstream added an input limit check. Installed **6.5+20250216-2** remains OPEN. [Upstream change](https://invisible-island.net/ncurses/NEWS.html#index-t20251213). |
| systemd — [CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742) | Requires a homed-managed local user's home-record authentication path. Inventory detects **libsystemd0/libudev1**, without the systemd-homed package; this narrows package context without proving file absence or deployment reachability. Remains OPEN. [Upstream advisory](https://github.com/systemd/systemd/security/advisories/GHSA-jm29-p7hh-vjhv). |
| Perl — [CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538) | Requires vulnerable `Archive::Tar` parsing an oversized crafted tar entry. Debian defers the fix pending upstream regression resolution; detecting perl-base alone does not establish affected-module presence or use. Remains OPEN, `fix_deferred`. [Upstream patch](https://github.com/jib/archive-tar-new/commit/f9af01426038e29d9578825a0cd3626946ab08c7). |

All MEDIUM, LOW and UNKNOWN findings also remain OPEN with their exact status and references in the machine evidence. Debian's `no-dsa` label concerns advisory priority; it does not establish that an installed package is fixed or unaffected. [Debian classification](https://security-team.debian.org/security_tracker.html#issues-not-warranting-a-security-advisory).

OS/package scanning does not independently cover every compiled-in or custom-built library. The existing native and embedded cryptography verification remains necessary. [Trivy Debian coverage](https://trivy.dev/docs/latest/coverage/os/debian/). No deployment exploit test, unrestricted production clearance or acceptance of these remaining advisories is claimed. The verified local repair is complete; the remaining field/security acceptance is OPEN and GA is NO_GO.
