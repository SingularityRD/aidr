---
"@singularityrd/aidr-cli": minor
"@singularityrd/aidr-core": minor
---

New command `aidr privacy scan [file]`: a local TR/EN personal-data and secret scan of one
file or standard input (TCKN, IBAN, phone, e-mail, payment card, secrets, private keys and
the other core DLP detectors). It prints type, count and line numbers and never a matched
value. `--json` gives offsets, `--mask` prints a `[TYPE]`-redacted copy, `--types` narrows
the detectors and `--fail-on none|any|secret` sets the gate. Exit codes: `0` clean, `2`
findings, `3` incomplete inspection (never reported as clean), `1` error. Core now exports
`detectOutputSensitiveData`.
