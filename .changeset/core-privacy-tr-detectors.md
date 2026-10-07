---
"@singularityrd/aidr-core": minor
---

Core DLP now includes the AIDR Privacy TR/EN detectors, taken from a generated copy of `packages/privacy/src/rules.ts` (`pnpm sync:privacy-rules`, checked with `pnpm verify:privacy-rules`).

Tenant DLP policies can use a new matcher type, `{ "type": "detector", "detectors": [...] }`. It supports TC Kimlik (checksum), IBAN (mod-97 for every registry country), TR/international phone numbers, email, credit card, US SSN, addresses, person names that appear next to context, labelled date-of-birth, passport, national ID, tax ID and bank-account fields, IP/MAC addresses, credential tokens (sk-proj, sk-ant-api, github_pat_, glpat-, JWT, Bearer, URL userinfo, `password=`/`şifre=`), PEM private keys and classification banners.

- Detector matches redact to a type placeholder such as `[TC_KIMLIK]` unless the rule sets its own `replacement`.
- JSON content is scanned one string at a time, and a sensitive key marks its whole string or number value.
- A scan that cannot inspect all of the content returns `unavailable` with the new reason `incomplete_inspection`.

`PiiDetectorImpl` gains `tc_kimlik`, `iban`, `private_key` and TR phone detection, all on by default. The `secret`, `address`, `person` and labelled-field types are opt-in through `enableSecret`, `enableAddress`, `enablePerson` and `enableLabelledFields`. With tenant DLP enabled, the tool-input PII gate therefore also blocks TC Kimlik and IBAN values.
