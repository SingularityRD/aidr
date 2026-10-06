# Singularity AIDR Privacy — 0.5.0-rc.1 (workspace import)

Local Turkish/English privacy controls and an integration-ready server control plane. **Tested release candidate, not a completed corporate production acceptance.**

This release extends 0.4 rather than replacing it. Text redaction, screenshot OCR redaction, browser/native controls and enterprise policy remain available. New modules add channel-bound identity, durable approvals/quota/audit, guarded provider dispatch, a review portal, text-only document reconstruction, authorized local discovery, source ACL synchronization, a small trained review classifier and model/audio safety helpers.

## Read first

- [Implemented vs. accepted: all 12 requested rows](docs/PLATFORM_FEATURE_STATUS.md)
- [Merge and trust-boundary guide](docs/PLATFORM_MERGE.md)
- [Narrow on-prem text service](docs/TEXT_SERVICE.md)
- [Executed tests and limitations](reports/platform/TEST_REPORT.md)
- [Threat models and unsupported modalities](docs/PLATFORM_THREAT_MODEL.md)
- [Model card](models/MODEL_CARD.md)
- [Technical sources](docs/PLATFORM_SOURCES.md)

From the AIDR repository root:

```bash
pnpm install --frozen-lockfile --ignore-scripts
pnpm --filter @singularity/aidr-privacy build
pnpm --filter @singularity/aidr-privacy test:all # Linux, Node 22.16+, Python and OpenSSL required
pnpm --filter @singularity/aidr-privacy demo:platform
```

This workspace import omits the generated `dist/` and Chrome bundle, raw test logs, npm lockfile, and vendored development tarballs; builds recreate the generated output. See [UPSTREAM.md](UPSTREAM.md) for the verified source snapshot. The npm runtime has no third-party runtime npm dependency. Optional Python/native dependencies and production NER models are NOT bundled. Linux-only document isolation requires libseccomp. The original Node test runtime was 22.16.0 and its node:sqlite API was experimental.

For Linux CDR tests, use a Python virtual environment created with `python3 -m venv --copies` and point `AIDR_PYTHON` to its real executable; the parser intentionally rejects symlinked executables. Install the pinned parser requirements plus test-only `reportlab==4.4.9`. Vision tests additionally need the documented Pillow/pyzbar and native OCR libraries; the QR fixture needs test-only `qrcode==8.2`.

```ts
import { createPlatformRuntime, listenPlatform } from '@singularity/aidr-privacy/platform';
```

The runtime defaults to defense mode: without approved learned TR/EN PERSON/ADDRESS NER coverage it does not release text. The included 464 KiB-class synthetic linear model is a supplementary review signal, not NER. The shipped synthetic qualification report is deliberately **false**, including two missed unlabelled names.

The new server gateway is not automatically injected into the pre-existing Chrome/native workflow or the main AIDR application's agent hooks. Real IdP/MDM/provider-account brokers, all first-upload/provider/tool exits, network restrictions and signed distribution still need integration and acceptance. Importing the package into the repository does not enable these controls for customers.

Prior documents and reports under `docs/enterprise`, `reports/enterprise`, `reports/browser`, `reports/visual` include historical release evidence. The current executed-evidence index is `reports/platform/TEST_REPORT.md`. Self-generated release hashes are integrity inventories, not corporate signatures.
