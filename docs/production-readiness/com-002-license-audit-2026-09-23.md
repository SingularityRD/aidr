# COM-002 licensing/IP audit — 23 September 2026

**Decision: open; no customer redistribution or legal approval inferred.** This is
a source-tree and local-release-tool audit, not a review by counsel.

| Boundary | Verified locally | Still required for the exact release candidate |
|---|---|---|
| First-party terms | Root `LICENSE`/`NOTICE`; ten workspace package manifests declare `Proprietary`; package-local licence variants exist. | Counsel-approved terms, package/notice reconciliation, contributor and employee/contractor chain of title. |
| npm dependencies | A lock-derived local SBOM contained 184 npm components, including workspaces; installed direct-runtime package metadata was inspected. | Full licence texts and required notices for the exact transitive packages in every distributed npm/VSIX/customer artifact. The current `THIRD_PARTY_NOTICES` is only a direct-dependency baseline. |
| Python bridge | The runtime lock contains 31 SHA-256-pinned PyPI packages. Update 2026-10-05: licence evidence (Core Metadata, `dist-info` licence-file digests, bundled `*.libs/`) is now extracted from the 31 hash-verified manylinux/cp312 wheels into `services/aig-bridge/pypi-runtime-licenses.json` (`scripts/extract-pypi-license-metadata.py`); `scripts/lib/pypi-license-data.mjs` maps it by exact tables only. 28 are permissive; **3 are weak copyleft and flagged**: `certifi` (MPL-2.0), `psycopg` and `psycopg-binary` (LGPLv3; the metadata does not say -only/-or-later so no SPDX id is recorded). `uvloop` is MIT and Apache-2.0 per its own description (operator unspecified; pinned reviewed resolution). Commercial SBOM generation now succeeds only when every package is classified, and fails on missing/stale evidence or any unknown. | Legal decision on MPL-2.0/LGPLv3 redistribution (notices, relinking/replacement obligations for the bridge image). `psycopg-binary` bundles 14 native libraries (libpq, OpenSSL, Kerberos, LDAP, SASL, PCRE ...) whose own licences the wheel metadata does not declare: inspect and list them or replace with source-built `psycopg[c]`. Shipped licence-file texts/notices still need to be placed in the image. `vendor/ai-infra-guard/mcp-scan/requirements-runtime.lock` (42 pins, a different platform set) is not in the SBOM and has no licence evidence yet. |
| Images and vendor code | The bridge Dockerfile pins its Python base digest; AIG source has a vendor Apache-2.0 `LICENSE` and attribution `NOTICE`; the customer kit copies the pinned Supabase upstream licence. | Container base/OS packages, Supabase/upstream images, AIG server components, pinned source provenance and all image-specific notices/SBOMs bound to the candidate. Confirm vendor attribution in each shipped surface. |
| Threat rules | `threats/LICENSE` carries DRL 1.1 and author/derived-output attribution terms. | Verify each distributed rule and detection output preserves required author/source attribution. |
| Exceptions and approval | The exception register honestly remains `open` with 15 unknown fields. | Named Legal owner/reviewer, disposition and expiry for any exception, signed approval tied to one clean candidate digest. |

The local `claim-check --mode=inventory`, commercial template validator, and
13-receipt structural validator pass, but `claim-check --mode=gate` fails as
designed because COM-002 and the other external gates are open. PyPI's JSON
release metadata alone is not sufficient evidence for an exact wheel: its
metadata need not match the uploaded distribution's contents. Use the
distribution's Core Metadata `License-Expression` and `License-File` plus the
actual licence files, then have Legal review the resulting candidate-bound
bundle. See [PyPI JSON API](https://docs.pypi.org/api/json/) and
[Python Core Metadata](https://packaging.python.org/en/latest/specifications/core-metadata/).
