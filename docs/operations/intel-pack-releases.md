# Intel pack releases (license-bound update packs)

How the vendor builds, signs, verifies and delivers intel update packs, how often,
and how a revoked license is kept from receiving new ones. The customer-side import
is described in [threat sync: air-gapped updates](threat-sync.md#air-gapped-updates);
the license terms that gate acceptance are in [licensing](licensing.md).

## What a pack is

A pack is a directory (or the single-file `aidr-intel-pack-bundle-v1` that carries
the same bytes) in the format the endpoint loader reads
(`packages/core/src/intel/loader.ts`):

- `manifest.json`: `pack_id`, `version`, signed `issued_at`, optional `expires_at`,
  `key_id`, optional `audience.customer_ids`, and `files[]` with the SHA-256 of
  every list (plus `ciphertext_sha256`, `cipher` and `key_id` for encrypted lists).
  A `source` block records the SHA-256 of the `threats/` rule set and of the curated
  intel data it was built from, the rule ids that contributed entries, and the
  entry count per list. The loader ignores `source`; the signature covers it.
- `manifest.sig`: Ed25519 signature over the exact manifest bytes.
- `lists/<kind>`: one file per intel kind.

The signature covers every manifest byte, so the audience, `issued_at` and
`expires_at` cannot be changed without invalidating it.

What goes in: the endpoint's intel kinds are lists (hosts, package names, SHA-256
digests, domain risk), not regex rules. The builder therefore takes the curated
intel data in `intel/` and, from `threats/*.yaml`, only rules that are an exact
host literal with `action: block` on `match_on: url` (these become URL denylist
entries). All other rules ship with the connector release; a pack never replaces
or removes a bundled rule.

### Curated intel data (`intel/`)

A closed set of file names; anything else is refused, and so is any entry that
does not parse (nothing is dropped silently):

| File | Kind | Entry |
|---|---|---|
| `url_denylist.txt` | `url_denylist` | host or URL per line |
| `url_allowlist.txt` | `url_allowlist` | host or URL per line (refused if also on the denylist) |
| `domain_risk.json` | `domain_risk` | JSON array of `{ domain, action: allow\|ask\|deny, severity, confidence?, reason? }` |
| `package_name_denylist.txt` | `package_name_denylist` | package name per line |
| `package_hash_denylist.txt` | `package_hash_denylist` | SHA-256 hex per line |
| `plugin_signature_denylist.txt` | `plugin_signature_denylist` | SHA-256 hex of a plugin file per line |

Lines starting with `#` are comments. `README.md` in the directory is ignored.

## Acceptance on endpoints

A new pack is installed only when all of these hold (`scripts/import-offline-pack.mjs`
and the core `acceptPack`):

1. the signature verifies against the publisher key in the operator's trusted-keys
   file, every file digest matches, the pack has not expired, and it is not older
   than the installed version;
2. its signed `issued_at` is at or before the license's `expires_at + grace_days`
   (only signed times are compared, never the endpoint clock);
3. if it has an audience, the license's `customer_id` is listed;
4. the license is not listed in the newest signed `aidr-license-revocations-v1`
   list the endpoint holds.

A refused pack changes nothing. Packs already installed keep enforcing whatever the
license state: expiry, an ended term and revocation only stop what comes next.

## License revocation list

`aidr-license-revocations-v1` is a vendor-signed list of revoked license ids:

```json
{
  "format": "aidr-license-revocations-v1",
  "key_id": "<license signing key id>",
  "payload": { "issued_at": "2026-10-14T09:00:00Z", "sequence": 5, "license_ids": ["LIC-2026-0007"] },
  "sig": "<base64 Ed25519 over 'aidr-license-revocations-v1\n' + canonical JSON of payload>"
}
```

- It is signed with a key from the license public-key registry
  (`deploy/onprem/license-public-keys.json`), with its own format prefix, so a
  license or customer-packet signature never verifies as a revocation list.
- It is complete, not a delta, and `sequence` increases with every issue. An
  endpoint keeps the list with the higher sequence
  (`~/.singularity-aidr/license-revocations.json`), so an older list cannot
  un-revoke a license.
- A list that does not verify refuses the import; it is never read as "nothing
  revoked".
- At most 1000 ids per list (the 64 KiB signed-document limit).

Issue one in the license-signing environment (same key handling as
`scripts/license-issue.mjs`):

```sh
node scripts/license-revocations-issue.mjs --key-id <license key id> --sequence <previous + 1> \
  --license-ids-file revoked-licenses.txt --public-keys deploy/onprem/license-public-keys.json \
  --out license-revocations.json
```

Then publish it with the next pack: set the base64 of the file as the
`AIDR_LICENSE_REVOCATIONS_B64` variable of the `intel-pack-signing` environment (or
pass it once as the `revocations_b64` workflow input). It is not a secret.

Boundary: revocation binds endpoints that import packs against a license (on-prem
and air-gapped). A customer who never imports the list, or never imports packs, is
not affected by it; their protection is the license term. Hosted and connected
delivery (`packs-manifest` / `packs-download`) is gated server-side by the tenant's
entitlement instead: switch off `premium_intel` for the tenant.

## Release cadence

| When | What |
|---|---|
| Every Monday 05:47 UTC (08:47 Türkiye) | Scheduled run of `.github/workflows/intel-pack-release.yml`: generic pack `aidr-intel`, version `<year>.<MMDD>.<run number>`, `expires_at` 45 days after issue, encrypted with the shared pack key. If there is nothing to ship, the run ends without a pack. |
| Out of band, when a confirmed indicator should not wait for Monday | Manual run (`workflow_dispatch`) with the same pipeline. The response time is set by the support agreement (TASLAK — business approval required), not by this pipeline. |
| On customer request / incident | Manual run with `audience` set to the customer id(s), producing `aidr-intel-<customer>` (several customers need an explicit `pack_id`). |

`expires_at` only marks an installed pack as stale on endpoints after 45 days
without an update; it keeps enforcing. Weekly releases keep every connected
installation well inside that window.

## The pipeline

```text
threats/*.yaml + intel/  ->  build  ->  encrypt (shared pack key)  ->  sign (--audience)
                         ->  verify (offline verifier, core loader, acceptPack self-test,
                                     revocation list)  ->  export  ->  draft release / control plane
```

1. **build**: `node scripts/intel-pack-release.mjs build --out <dir> --pack-id <id> --version <v> --key-id <publisher key id> [--intel-dir intel] [--audience <customer id>]... [--expires-in-days 45]`.
   Refuses an empty pack (`--if-empty skip` turns that into a no-op for scheduled runs), an
   existing output directory and any invalid entry.
2. **encrypt** (optional): `node scripts/intel-pack-keys.mjs encrypt-pack --pack <dir> --shared-key-file <file>`.
3. **sign**: `node scripts/sign-intel-pack-manifest.mjs --manifest <dir>/manifest.json --private-key <0600 pem> --audience <ids|none>`.
   The signer refuses a manifest whose audience is not exactly the one given, or that has no `issued_at`.
   `<trusted-keys.json>` is a JSON map of key id to public-key PEM,
   `{"<key_id>": "-----BEGIN PUBLIC KEY-----\n..."}` (the same form threat-sync uses);
   a bare PEM file is refused as "not JSON".
4. **verify**: `node scripts/intel-pack-release.mjs verify --pack <dir> --trusted-keys <trusted-keys.json> [--shared-key-file <file>] [--license-public-keys <registry> --license-revocations <list>] --report <file>`.
   - the offline importer's verifier (signature against the *published* public key,
     digests, expiry);
   - the core loader in a disposable HOME: it must report the pack available and load
     exactly the entry counts the signed manifest declares; a copy with one changed
     manifest byte must be refused;
   - core `acceptPack` against sample licenses signed with a throwaway key: in-term
     accepted, out-of-term refused (`license_term_ended`), another customer refused
     for an audience pack (`pack_audience_mismatch`), a revoked license refused
     (`license_revoked`);
   - the real revocation list, when given, against the license registry.
5. **export**: `node scripts/intel-pack-release.mjs export --pack <dir> --trusted-keys <trusted-keys.json> --out <dir> [...]`
   writes `<pack_id>-<version>.aidrpack.json`, `intel-trusted-keys.json`,
   `license-revocations.json` (if any), `IMPORT.txt` (EN/TR) and `SHA256SUMS`. This
   folder is both the release assets and the offline bundle for air-gapped customers;
   it can also be added to a full air-gap transfer with
   `scripts/onprem-offline-bundle.mjs build --intel-pack <bundle>`.

## GitHub workflow setup

`.github/workflows/intel-pack-release.yml` runs only from the protected default branch.

| Environment | Kind | Name | Content |
|---|---|---|---|
| `intel-pack-signing` | secret | `AIDR_INTEL_PACK_SIGNING_KEY` | publisher Ed25519 private key (PEM) |
| `intel-pack-signing` | secret | `AIDR_INTEL_SHARED_PACK_KEY` | `aidr-shared-pack-<label>=<base64>` from `intel-pack-keys.mjs new-shared-key` |
| `intel-pack-signing` | variable | `AIDR_INTEL_PACK_KEY_ID` | publisher key id (the key endpoints trust) |
| `intel-pack-signing` | variable | `AIDR_INTEL_PACK_PUBLIC_KEY_PEM` | publisher public key, as shipped to customers |
| `intel-pack-signing` | variable | `AIDR_LICENSE_PUBLIC_KEYS_JSON` | optional; default `deploy/onprem/license-public-keys.json` |
| `intel-pack-signing` | variable | `AIDR_LICENSE_REVOCATIONS_B64` | optional; the current signed revocation list |
| `intel-pack-publish` | variable | `AIDR_CONTROL_PLANE_SUPABASE_URL` | hosted control plane URL (https) |
| `intel-pack-publish` | secret | `AIDR_CONTROL_PLANE_SERVICE_ROLE_KEY`, `AIDR_CONTROL_PLANE_ANON_KEY` | control plane credentials |

Give `intel-pack-publish` required reviewers. The signing key is written to a 0600
file in `RUNNER_TEMP` for the signing step only and removed after it; verification
uses the published public key variable, never a key derived from the secret.

Jobs:

- **build**: build, encrypt, sign, verify, export; attests the release files
  (build provenance) and uploads them as the `intel-pack-<pack_id>-<version>`
  artifact. The verification report is in the job summary.
- **publish-release**: checks `SHA256SUMS` and creates a **draft** GitHub release
  `intel-pack-<pack_id>-<version>` with every file. A person reviews
  `verification-report.json` and publishes the draft.
- **publish-control-plane** (manual runs with `publish_control_plane`, generic packs
  only, after `intel-pack-publish` approval): re-verifies the bundle and registers it
  with `scripts/import-offline-pack.mjs --target storage` in the private
  `aidr-packs` bucket and `pack_versions`, so `packs-manifest` / `packs-download`
  serve it to tenants with `premium_intel`. Customer packs (with an audience) are
  delivered as files and imported against the customer's license.

## Runbook

**Weekly release**

1. Monday: open the scheduled run. If it reports "No intel entries to publish", stop.
2. Read the verification report in the job summary: `loader.availability` is
   `available`, `tampered_copy` is `refused`, and `acceptance` is
   `in_term: accepted`, `out_of_term: license_term_ended`,
   `other_customer: accepted` (generic) or `pack_audience_mismatch` (customer pack),
   `revoked_license: license_revoked`.
3. Publish the draft release. For the hosted service, run the workflow manually
   with `publish_control_plane` for the same content, or register the published
   bundle with `import-offline-pack.mjs --target storage`.
4. Air-gapped customers: deliver the release folder on approved media; they run
   `sha256sum --check SHA256SUMS` and follow `IMPORT.txt`.

**Revoking a license**

1. Add the license id to the revocation source file and issue a list with the next
   `sequence` (above).
2. Update `AIDR_LICENSE_REVOCATIONS_B64` and run the workflow manually (or wait for
   the next scheduled run); every release after that carries the list.
3. For hosted or connected tenants of that customer, switch off `premium_intel`.

**A pack must be withdrawn**

1. Publish a new version without the bad entries (a higher version replaces it on
   import; rollback to an older version is refused).
2. If the signing key is suspected, rotate it: new `AIDR_INTEL_PACK_SIGNING_KEY` /
   key id / public key, ship the new trusted-keys file, and refuse the old key on
   import with `--revoked-key-id`.

**A run fails**

| Message | Cause | Fix |
|---|---|---|
| `the pack would carry no intel entries` | manual run with no curated data | add data under `intel/` |
| `is on both the URL denylist and the URL allowlist` | conflicting curated entries | remove one |
| `does not match --audience` | audience input and manifest differ | re-run; do not edit manifests by hand |
| `offline verifier refused the pack: ... signature does not verify` | public key variable does not match the signing secret | fix the variables |
| `the core loader loaded N ... entries, the signed manifest declares M` | a list the endpoint would not parse as built | fix the data or the builder; do not publish |
| `license revocation list does not verify` | list signed with a key missing from the registry, or edited | re-issue it with an active registry key |

## Needs a person

- Generating and holding the publisher signing key, the shared pack key and the
  license signing key (in the license-signing environment, not on a laptop).
- Creating the `intel-pack-signing` and `intel-pack-publish` environments, their
  secrets and reviewers.
- Curating `intel/` (sources, review) and publishing each draft release.

## Türkçe özet

Tehdit bilgisi güncelleme paketleri her pazartesi 08:47'de (TSİ) otomatik olarak
üretilir, imzalanır ve uç noktanın kendi yükleyicisi ile doğrulanır; ayrıca acil bir
gösterge için aynı gün elle yayımlanabilir. Yayın, bir kişinin doğrulama raporunu
inceleyip onayladığı bir taslak olarak oluşturulur. İnternetsiz kurulumlar yayın
klasörünü onaylı bir ortamla alır, `sha256sum --check SHA256SUMS` ile doğrular ve
`IMPORT.txt` adımlarını izler.

Yeni bir paket yalnızca imzası ve özetleri doğrulanırsa, lisansın güncelleme süresi
(bitiş + ek süre) içinde yayımlandıysa, belirli müşteriler için yayımlandıysa bu
müşteri listede yer alıyorsa ve lisans imzalı iptal listesinde değilse kurulur.
Reddedilen paket hiçbir şeyi değiştirmez; kurulu paketler her durumda korumaya devam
eder. İptal listesi (`aidr-license-revocations-v1`) lisans imza anahtarıyla
imzalanır, her yayında sıra numarası artar ve uç nokta daha eski bir listeye geri
dönmez.
