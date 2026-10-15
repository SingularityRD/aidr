# AIDR Privacy

`@singularityrd/aidr-privacy` 0.6.0 is the content-privacy engine of Singularity AIDR. It
finds and masks Turkish and English personal data and secrets in text, and it is the
engine behind three product surfaces:

- **Browser Guard** reuses its browser-safe rule layer (detectors, validators,
  normalization, span merging, literal dictionary) to inspect prompts, pastes and uploads
  before they reach an AI site.
- **Core DLP** (`@singularityrd/aidr-core`) adopts its TR/EN detectors (T.C. kimlik
  numbers, IBANs, Turkish phone numbers and addresses, labelled fields, provider tokens,
  private keys) through a generated, drift-checked copy of the rule files, so every agent
  connector gets the same detection.
- **Optional enterprise layer**: a server-side gateway / control plane
  (`@singularityrd/aidr-privacy/platform`), signed enterprise policy and tool controls
  (`/enterprise`), and a Chrome native-messaging host for OCR and document handling. These
  are opt-in integration building blocks, not controls that are switched on for customers
  by installing AIDR.

It is a private workspace package (`"private": true`, not published to npm). Its `dist/` is
part of the release artifact set: `pnpm build:release` builds it without source maps, writes
`dist/aidr-artifact.manifest.json`, and runs the same package-contract, source-map and
leaky-path checks as the other release packages.

## Status

Honest summary for 0.6.0. "Tested" means automated tests in this repository exercise the
code; it does not mean a customer has accepted it in production.

| Capability | Where | Status |
|---|---|---|
| TR/EN text detection and masking (checksum-validated TCKN, IBAN mod-97, Luhn cards, phones, addresses, labelled fields, secrets) | `src/detectors.ts`, `src/engine.ts` | Tested (`pnpm test:privacy`) |
| Browser-safe rule layer (no `node:` imports) | `src/{types,errors,normalize,detectors,validators,dictionary,spans,ip,json}.ts` | Tested; consumed by Browser Guard |
| Core DLP TR/EN detectors | `packages/core/src/dlp/` (generated copy) | Integrated in 0.6.0; covered by core tests and a drift check |
| CLI privacy scan (`aidr privacy scan`) | `packages/cli/src/commands/privacy.ts` | Integrated in 0.6.0: core TR/EN detectors plus the output credential detector over one file or stdin (4 MiB cap); local only, values never printed, `--mask` redaction, exit `3` on incomplete inspection. Tested (`packages/cli/src/__tests__/privacy-scan.test.ts`) |
| Screenshot OCR redaction (`/visual`) | `src/visual/`, `vision/` | Tested with fake workers; real OCR needs the optional Python/native stack |
| Server gateway, review portal, durable state (`/platform`) | `src/platform/`, `portal/` | Tested locally; not wired into AIDR connectors; needs customer IdP/MDM/provider brokers ([status](docs/PLATFORM_FEATURE_STATUS.en.md)) |
| Enterprise policy and tool controls (`/enterprise`) | `src/enterprise/` | Tested; integration building block |
| Legacy Chrome MV3 extension and native host | `extension/`, `src/native/` | Builds and is tested with mocked Chrome APIs; unsigned; its bundle still carries the 0.5.0-rc.1 build label. Browser Guard is the supported browser product |
| Document CDR parser | `parsers/` | Linux-only; tests skip explicitly without Python parser packages or libseccomp |
| Learned PERSON/ADDRESS NER | `ner/` | Not bundled; `defense` profile refuses to release text without it |
| AIDR Privacy companion (Windows, per user): native host + Windows built-in OCR for Browser Guard | `src/companion/`, `native/windows/`, `vision/windows_ocr.ps1` | Installed and verified on Windows 11 (real launcher, real Chrome-style start, real Chromium E2E); tests in `tests/companion/`. Unsigned launcher; barcode detection needs the VC++ 2013 runtime (see below) |

## Read first

- [Implemented vs. accepted: all 12 requested rows](docs/PLATFORM_FEATURE_STATUS.en.md) ([Turkish original](docs/PLATFORM_FEATURE_STATUS.md))
- [Merge and trust-boundary guide](docs/PLATFORM_MERGE.md)
- [Narrow on-prem text service](docs/TEXT_SERVICE.md)
- [Executed tests and limitations](reports/platform/TEST_REPORT.md)
- [Threat models and unsupported modalities](docs/PLATFORM_THREAT_MODEL.md)
- [Model card](models/MODEL_CARD.md)
- [Technical sources](docs/PLATFORM_SOURCES.md)

From the AIDR repository root:

```bash
pnpm install --frozen-lockfile --ignore-scripts
pnpm test:privacy # build + every Node suite; missing Python/OpenSSL/libseccomp prerequisites are reported as named skips
pnpm --filter @singularityrd/aidr-privacy build
pnpm --filter @singularityrd/aidr-privacy test:all # full coverage needs Linux, Node 22.16+, Python parser packages, libseccomp and OpenSSL
pnpm --filter @singularityrd/aidr-privacy demo:platform
```

This workspace import omits the generated `dist/` and Chrome bundle, raw test logs, npm lockfile, and vendored development tarballs; builds recreate the generated output. See [UPSTREAM.md](UPSTREAM.md) for the verified source snapshot. The npm runtime has no third-party runtime npm dependency. Optional Python/native dependencies and production NER models are NOT bundled. Linux-only document isolation requires libseccomp. The original Node test runtime was 22.16.0 and its node:sqlite API was experimental.

For Linux CDR tests, use a Python virtual environment created with `python3 -m venv --copies` and point `AIDR_PYTHON` to its real executable; the parser intentionally rejects symlinked executables. Install the pinned parser requirements plus test-only `reportlab==4.4.9`. Vision tests additionally need the documented Pillow/pyzbar and native OCR libraries; the QR fixture needs test-only `qrcode==8.2`.

```ts
import { createPlatformRuntime, listenPlatform } from '@singularityrd/aidr-privacy/platform';
```

The runtime defaults to defense mode: without approved learned TR/EN PERSON/ADDRESS NER coverage it does not release text. The included 464 KiB-class synthetic linear model is a supplementary review signal, not NER. The shipped synthetic qualification report is deliberately **false**, including two missed unlabelled names.

The new server gateway is not automatically injected into the pre-existing Chrome/native workflow or the main AIDR application's agent hooks. Real IdP/MDM/provider-account brokers, all first-upload/provider/tool exits, network restrictions and signed distribution still need integration and acceptance. Importing the package into the repository does not enable these controls for customers.

Prior documents and reports under `docs/enterprise`, `reports/enterprise`, `reports/browser`, `reports/visual` include historical release evidence. The current executed-evidence index is `reports/platform/TEST_REPORT.md`. Self-generated release hashes are integrity inventories, not corporate signatures.
