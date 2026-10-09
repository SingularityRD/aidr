---
"@singularityrd/aidr-cli": patch
"@singularityrd/aidr-core": patch
---

`aidr audit verify` now uses one exit-code contract in both modes: `0` verified, `1` broken (tampered, missing, reordered or truncated record), `2` unverifiable (configuration or log unreadable, log or signing key missing, or no signed chain enabled). The default both-chains mode previously exited `1` for every failure, including "no chain enabled" and an unreadable configuration; scripts that treated any non-zero exit as a failure are unaffected. Its `--json` output reports an unverifiable response chain as `status: "unverifiable"` instead of `"failed"`.

A shell command containing a validly encoded U+FFFD (replacement character) is no longer rejected as malformed. Undecodable hook input is still refused fail-closed by the strict UTF-8 decode every connector applies to raw stdin bytes; NUL bytes and unpaired surrogates in a command are still denied.
